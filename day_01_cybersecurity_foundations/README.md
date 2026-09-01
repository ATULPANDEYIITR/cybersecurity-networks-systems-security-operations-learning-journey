# Cybersecurity Foundations

## Complete Learning Notes

This lesson establishes the conceptual foundation required before studying network security, penetration testing, security operations, cloud security, application security, digital forensics, incident response, and advanced cybersecurity architecture.

---

# 1. What Is Cybersecurity?

Cybersecurity is the discipline of protecting:

* Information
* Computers
* Networks
* Applications
* Cloud infrastructure
* Devices
* Identities
* APIs
* Digital services
* Business processes

against unauthorized access, disclosure, modification, destruction, disruption, and misuse.

A useful mental model is:

```text
                    ASSETS
                       |
                       v
                    THREATS
                       |
                       v
                VULNERABILITIES
                       |
                       v
                     RISK
                       |
                       v
                   CONTROLS
                       |
                       v
                 REDUCED RISK
```

Cybersecurity is not simply antivirus software or firewalls.

It involves technology, people, processes, governance, architecture, risk management, and incident response.

---

# 2. Core Cybersecurity Vocabulary

## Asset

An asset is something valuable that requires protection.

Examples:

* Customer database
* Laptop
* Server
* API
* Password
* Source code
* Financial information
* Intellectual property
* Cloud account

---

## Threat

A threat is something capable of causing harm.

Examples:

* Cybercriminal
* Malicious insider
* Malware
* Natural disaster
* Hardware failure
* Compromised third party

---

## Vulnerability

A vulnerability is a weakness that could contribute to compromise or harm.

Examples:

* Weak password
* Missing security update
* Excessive privileges
* Poor access control
* Misconfigured cloud storage
* Vulnerable software dependency

---

## Risk

Risk describes potential loss or harm associated with threats exploiting vulnerabilities.

A simplified model is:

```text
Risk ≈ Likelihood × Impact
```

This is an educational model, not a universal risk equation.

Professional risk analysis can consider:

* Asset value
* Threat likelihood
* Exploitability
* Exposure
* Business impact
* Existing controls
* Detection capability
* Recovery capability
* Uncertainty

---

# 3. CIA Triad

CIA stands for:

```text
C = Confidentiality
I = Integrity
A = Availability
```

These are fundamental information-security objectives.

---

# 4. Confidentiality

Confidentiality means preventing unauthorized disclosure of information.

Example:

An employee should not be able to read confidential HR salary records unless authorized.

Controls supporting confidentiality include:

* Authentication
* Authorization
* Encryption
* Access control
* Data classification
* Network segmentation
* Least privilege
* Data-loss prevention

### Confidentiality failure

```text
Unauthorized person
        |
        v
Reads confidential data
        |
        v
Confidentiality breach
```

Encryption can support confidentiality, but confidentiality is broader than encryption.

---

# 5. Integrity

Integrity means maintaining the accuracy, completeness, consistency, and trustworthiness of information.

Example:

```text
Original transaction:
Rs. 10,000

Unauthorized modification:

Rs. 1,00,000
```

This is an integrity problem.

Controls include:

* Hashes
* HMAC
* Digital signatures
* Database constraints
* Access controls
* File permissions
* Change management
* Version control
* Audit logging

A hash can help detect modification, but a hash alone does not establish who created the data.

---

# 6. Availability

Availability means authorized users can access systems and information when needed.

Availability controls include:

* Redundancy
* Backups
* Disaster recovery
* Failover
* Load balancing
* Capacity planning
* Monitoring
* DDoS protection
* Power redundancy

Availability failures include:

* Server outage
* Network failure
* Hardware failure
* Ransomware
* Resource exhaustion
* Infrastructure failure

---

# 7. CIA Trade-offs

Security properties can conflict.

For example:

```text
More restrictive access
        |
        +--> Better confidentiality
        |
        +--> Potentially worse usability
        |
        +--> Potentially reduced availability
```

Security engineering balances:

* Security
* Availability
* Usability
* Performance
* Cost
* Compliance
* Business requirements

---

# 8. Authenticity

Authenticity answers:

> Is this entity or message genuinely what it claims to be?

Examples:

* Is this really Alice?
* Is this really the organization's server?
* Did this message originate from the claimed source?

Authentication is related to authenticity.

---

# 9. Authentication vs Authorization

These concepts must not be confused.

## Authentication

Answers:

> Who are you?

Examples:

* Password
* PIN
* Hardware security key
* Biometric
* Certificate

## Authorization

Answers:

> What are you allowed to do?

Example:

Alice successfully logs into the system.

Authentication:

```text
Alice is Alice.
```

Authorization:

```text
Alice can view her account.

Alice cannot modify another customer's account.
```

A user can be successfully authenticated and still be denied an action.

---

# 10. Authentication Factors

Common authentication-factor categories include:

### Something you know

Examples:

* Password
* PIN

### Something you have

Examples:

* Security key
* Hardware token
* Mobile device

### Something you are

Examples:

* Fingerprint
* Facial biometric

Other contextual factors can include:

* Location
* Behavioral characteristics

---

# 11. Multi-Factor Authentication

MFA combines independent authentication factors.

Example:

```text
Password
   +
Security key
```

This is stronger than:

```text
Password
   +
Another password
```

because two passwords belong to the same factor category.

---

# 12. Accountability

Accountability means being able to associate actions with responsible identities, systems, or processes.

A mature security environment should help answer:

```text
Who?
What?
When?
Where?
Which system?
Which resource?
What result?
Was it authorized?
What evidence remains?
```

Common accountability mechanisms:

* User identities
* Audit logs
* Authentication logs
* Database logs
* Endpoint telemetry
* SIEM systems
* Change records
* Privileged access management

---

# 13. Audit Logging

A useful audit event might contain:

```text
Timestamp:
2026-09-01 20:30:00

User:
alice

Action:
READ

Resource:
customer_database

Result:
SUCCESS

Source:
application-server-01
```

This is much more useful than:

```text
Someone accessed the database.
```

Logs themselves must be protected.

If attackers can modify or delete logs, accountability and incident investigation become much harder.

---

# 14. Non-Repudiation

Non-repudiation concerns evidence supporting the origin, integrity, or occurrence of an action or communication.

Digital signatures are an important technical mechanism.

Conceptually:

```text
Sender
   |
   | Private Key
   v
Digital Signature
   |
   v
Message
   |
   v
Receiver
   |
   | Public Key
   v
Verification
```

Non-repudiation can depend on more than cryptography.

It may also involve:

* Key management
* Certificates
* Trusted timestamps
* Audit evidence
* Secure signing procedures
* Organizational controls
* Legal frameworks

---

# 15. Authentication, Accountability, and Non-Repudiation

These concepts are related but different.

| Concept         | Main Question                                        |
| --------------- | ---------------------------------------------------- |
| Authentication  | Who are you?                                         |
| Authorization   | What can you do?                                     |
| Accountability  | What did you do?                                     |
| Non-repudiation | What evidence supports that you performed an action? |

---

# 16. Core Security Principles

## Least Privilege

Give users, applications, and processes only the permissions they need.

Example:

A reporting application should not have permission to delete the entire production database.

---

## Need to Know

Access to information should be granted when it is genuinely required.

---

## Defense in Depth

Use multiple layers of security.

```text
Physical Security
       |
       v
Network Security
       |
       v
Identity Security
       |
       v
Endpoint Security
       |
       v
Application Security
       |
       v
Data Security
       |
       v
Monitoring
       |
       v
Incident Response
       |
       v
Recovery
```

If one layer fails, another may still prevent, detect, or contain the problem.

---

## Secure by Design

Security should be considered during architecture and development rather than added at the end.

---

## Secure by Default

Default configurations should minimize unnecessary exposure.

---

## Fail Secure

When a security decision cannot be made safely, systems should generally avoid granting unauthorized access.

Example:

```text
Authorization service unavailable
            |
            v
       Access denied
```

The exact failure behavior must still account for availability and safety requirements.

---

## Separation of Duties

Sensitive activities can be divided among multiple people or roles.

Example:

```text
Person A:
Creates financial transaction

Person B:
Approves financial transaction
```

This reduces the risk of one compromised account controlling the entire process.

---

## Complete Mediation

Access to protected resources should be checked according to the applicable authorization policy rather than assuming previous access automatically remains valid.

---

## Economy of Mechanism

Prefer security mechanisms that are sufficiently simple to understand, maintain, and verify.

---

## Open Design

Security should not depend primarily on keeping the design secret.

Protected secrets should remain secret, but the security of the design should not rely on nobody understanding how the system works.

---

## Zero Trust

Zero Trust means avoiding automatic trust based solely on network location or previous access.

Important ideas:

* Verify explicitly
* Use least privilege
* Assume breach

---

# 17. Threat vs Vulnerability vs Risk

The distinction is critical.

```text
THREAT
Potential source of harm

VULNERABILITY
Weakness

RISK
Potential consequence from the interaction between threats,
vulnerabilities, assets, and business impact
```

Example:

```text
Asset:
Customer database

Threat:
Unauthorized user

Vulnerability:
Excessive permissions

Impact:
Customer records modified

Risk:
Potential business loss resulting from unauthorized modification
```

---

# 18. Risk Matrix

A simple educational matrix can use:

```text
Risk = Likelihood × Impact
```

Both can be scored from 1 to 5.

Example:

```text
Likelihood = 4
Impact = 5

Risk = 4 × 5

Risk = 20
```

A simple educational classification could be:

```text
1–4      LOW
5–9      MEDIUM
10–16    HIGH
17–25    CRITICAL
```

Organizations may use completely different scoring systems.

---

# 19. Technical Severity vs Business Risk

A vulnerability's technical severity does not automatically determine its business risk.

Consider:

```text
System A:
Internal testing server

System B:
Core banking database
```

The same technical weakness could have dramatically different consequences.

Business risk can involve:

* Financial loss
* Operational disruption
* Legal consequences
* Regulatory impact
* Privacy impact
* Reputation damage
* Customer loss
* Safety impact

Cybersecurity professionals must translate technical findings into business consequences.

---

# 20. Risk Treatment

Four common risk-treatment approaches are:

## Avoid

Stop the activity creating unacceptable risk.

## Mitigate

Implement controls to reduce likelihood or impact.

## Transfer

Shift some consequences through contracts, insurance, or other arrangements.

## Accept

Knowingly retain the risk within approved limits.

Risk acceptance should be a conscious management decision, not an accidental outcome.

---

# 21. Residual Risk

Residual risk is the risk remaining after controls are implemented.

Example:

```text
Initial Risk
     |
     v
    HIGH
     |
     v
MFA + Monitoring + Least Privilege
     |
     v
   MEDIUM
```

Controls rarely eliminate all risk.

The organization must determine whether the remaining risk is acceptable.

---

# 22. Attack Surface

Attack surface is the collection of exposed points through which an unauthorized party could potentially interact with or influence a system.

It includes much more than network ports.

Examples:

* Web applications
* APIs
* Mobile applications
* Cloud services
* User accounts
* Administrative interfaces
* Remote access
* Endpoints
* Software dependencies
* Third-party integrations
* Identity systems
* CI/CD pipelines
* Physical interfaces
* Human processes

---

# 23. Attack Surface Categories

## Network Attack Surface

Examples:

* Network interfaces
* Services
* Remote access systems
* Internet-facing infrastructure

## Application Attack Surface

Examples:

* Login pages
* APIs
* File uploads
* Administrative interfaces
* Third-party libraries

## Identity Attack Surface

Examples:

* User accounts
* Privileged accounts
* Service accounts
* Authentication systems

## Cloud Attack Surface

Examples:

* Public cloud resources
* IAM policies
* APIs
* Storage configurations
* Management interfaces

## Human Attack Surface

Examples:

* Phishing susceptibility
* Social engineering
* Weak operational procedures
* Poor credential practices

---

# 24. Attack Surface Reduction

Ways to reduce unnecessary exposure include:

* Remove unused services
* Disable unused accounts
* Remove unnecessary interfaces
* Restrict administrative access
* Apply least privilege
* Patch vulnerable software
* Remove unsupported software
* Secure APIs
* Segment networks
* Secure cloud configurations
* Monitor exposed assets
* Control third-party integrations
* Use secure configuration baselines

Attack-surface management must be continuous.

A newly deployed API can create a new exposure tomorrow even if today's environment is secure.

---

# 25. Asset Inventory

A security team should know what it owns and exposes.

Example inventory:

| Asset           | Category    | Exposure         | Security Concern                 |
| --------------- | ----------- | ---------------- | -------------------------------- |
| Web Application | Application | Internet         | Authentication and authorization |
| Employee Laptop | Endpoint    | External network | Malware and credentials          |
| Cloud Storage   | Cloud       | API/Internet     | IAM and configuration            |
| Third-party API | Integration | External         | Authentication and data exchange |

The basic principle is:

> You cannot reliably protect what you do not know exists.

---

# 26. Windows Security Foundations

Important Windows security concepts include:

* User accounts
* Groups
* Administrators
* Windows Defender
* Windows Firewall
* User Account Control
* NTFS permissions
* Security Event Logs
* PowerShell
* Windows Update
* Group Policy
* BitLocker
* Credential protection

Useful defensive commands include:

```powershell
whoami
hostname
ipconfig
systeminfo
tasklist
```

PowerShell examples:

```powershell
Get-Process
Get-Service
Get-WinEvent
```

These help you understand the security state of a Windows system.

---

# 27. Kali Linux Foundations

Kali Linux is a Debian-based Linux distribution designed for security testing, digital forensics, research, and related activities.

For foundational learning, focus first on Linux itself.

Important concepts:

* Users
* Groups
* Files
* Permissions
* Processes
* Services
* Networking
* Logs
* Package management
* Shell
* Environment variables
* SSH
* sudo

Useful commands:

```bash
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
```

Do not focus on memorizing hundreds of security tools.

Understand the operating system first.

---

# 28. Hashing and Integrity

A cryptographic hash creates a fixed-size digest from data.

Example:

```text
Input
  |
  v
SHA-256
  |
  v
Digest
```

If the input changes:

```text
Original data
     |
     v
Hash A

Modified data
     |
     v
Hash B
```

Hash A and Hash B should differ.

Hashing can support integrity verification.

A hash does not automatically provide:

* Confidentiality
* Authorization
* Authentication
* Non-repudiation

---

# 29. HMAC

HMAC combines a cryptographic hash function with a secret key.

Conceptually:

```text
Message + Secret Key
        |
        v
       HMAC
```

HMAC can provide:

* Message integrity
* Authentication between parties sharing the secret

HMAC does not normally provide non-repudiation because both parties possess the shared secret.

Digital signatures use asymmetric cryptography and provide a different security property.

---

# 30. Security Controls

Controls can be classified according to purpose.

## Preventive

Designed to prevent unwanted events.

Examples:

* Access control
* MFA
* Firewall

## Detective

Designed to detect suspicious or unwanted activity.

Examples:

* SIEM
* Audit logging
* Monitoring

## Corrective

Designed to correct problems.

Examples:

* Removing malicious software
* Restoring correct configurations

## Recovery

Designed to restore operations.

Examples:

* Backup restoration
* Disaster recovery

## Deterrent

Designed to discourage unwanted activity.

Examples:

* Warning banners
* Visible security controls
* Organizational policies

## Compensating

Alternative controls used when the preferred control cannot be implemented.

---

# 31. Security Events vs Security Incidents

A security event is an observable occurrence.

Examples:

```text
Successful login
Failed login
File access
Firewall block
Password change
```

Not every event is an incident.

Example:

```text
One failed login
       |
       v
Normal event
```

But:

```text
Hundreds of failed logins
       +
Unusual source
       +
Sensitive account
       |
       v
Potential security incident
```

---

# 32. Security Logging

Security logs should generally provide:

* Timestamp
* Identity
* Source
* Action
* Target
* Result
* Relevant context

Logs should also be:

* Protected
* Retained appropriately
* Searchable
* Monitored
* Correlated where appropriate
* Time synchronized

Logging supports:

* Accountability
* Detection
* Investigation
* Incident response
* Compliance

---

# 33. Threat Modeling

Threat modeling is a structured approach to identifying potential security problems.

A simplified process:

```text
1. Identify assets
        |
        v
2. Identify trust boundaries
        |
        v
3. Understand data flows
        |
        v
4. Identify threats
        |
        v
5. Identify vulnerabilities
        |
        v
6. Analyze risk
        |
        v
7. Design controls
        |
        v
8. Validate controls
        |
        v
9. Reassess
```

Important questions:

* What are we protecting?
* Who might attack it?
* How can they reach it?
* What can go wrong?
* What would be the impact?
* Which controls reduce the risk?

---

# 34. STRIDE

STRIDE is a threat-modeling mnemonic.

```text
S = Spoofing
T = Tampering
R = Repudiation
I = Information Disclosure
D = Denial of Service
E = Elevation of Privilege
```

It provides a structured way to think about possible threats.

---

# 35. Dangerous Security Assumptions

Security failures often result from incorrect assumptions.

Examples:

```text
"The internal network is trusted."

"The URL is secret."

"Our application is too small to attack."

"The firewall solves everything."

"Encryption means the whole system is secure."

"Logs are automatically trustworthy."

"Low technical severity always means low business risk."
```

Good security engineering continuously challenges assumptions.

---

# 36. Security Through Obscurity

Hiding something is not a substitute for strong security.

Example:

Changing:

```text
/admin
```

to:

```text
/secret-management-panel-123
```

does not replace:

* Authentication
* Authorization
* MFA
* Logging
* Secure configuration

Security should depend on strong security mechanisms rather than secrecy of implementation details.

---

# 37. Secure Failure

Security systems must consider what happens when components fail.

Example:

```text
Authorization service fails
        |
        v
What should application do?
```

For sensitive resources, denying access may be safer.

But security decisions must also consider availability and safety.

Therefore:

> Fail-secure is a principle, not a universal instruction to ignore availability requirements.

---

# 38. Security Architecture

Security architecture distributes controls across layers.

A simplified model:

```text
Users
  |
  v
Identity
  |
  v
Access Policies
  |
  v
Application
  |
  v
API Gateway
  |
  v
Services
  |
  v
Data
  |
  v
Backups
```

Cross-cutting controls include:

* Authentication
* Authorization
* Encryption
* Logging
* Monitoring
* Configuration management
* Incident response

---

# 39. Security Goal to Control Mapping

| Security Goal   | Example Controls                                 |
| --------------- | ------------------------------------------------ |
| Confidentiality | Encryption, access control, least privilege      |
| Integrity       | Hashing, HMAC, signatures, change control        |
| Availability    | Redundancy, backup, failover                     |
| Authenticity    | Authentication, certificates, MFA                |
| Accountability  | Logging, audit trails, identity management       |
| Non-repudiation | Digital signatures, trusted timestamps, evidence |

---

# 40. Defense in Depth

A strong architecture does not rely on a single security control.

Example:

```text
Stolen Password
       |
       v
MFA
       |
       v
Conditional Access
       |
       v
Endpoint Detection
       |
       v
Monitoring
       |
       v
Incident Response
```

If one control fails, other layers can reduce the impact.

---

# 41. Zero Trust

Zero Trust can be summarized using three major ideas:

```text
Verify explicitly
Use least privilege
Assume breach
```

Network location should not automatically establish trust.

An access decision can consider:

* User identity
* Device
* Application
* Resource
* Authentication strength
* Location
* Time
* Risk signals
* Security policy

---

# 42. End-to-End Case Study: Online Banking

Consider an online banking system.

## Assets

* Customer identities
* Account balances
* Transaction records
* Credentials
* APIs
* Audit logs

## Threats

* Cybercriminals
* Malicious insiders
* Compromised devices
* Third-party compromise
* Administrative mistakes

## Vulnerabilities

* Weak authentication
* Excessive permissions
* Poor input validation
* Cloud misconfiguration
* Exposed administration interfaces

---

## CIA Analysis

### Confidentiality

Customer information must not be disclosed to unauthorized parties.

### Integrity

Transactions and account balances must not be improperly modified.

### Availability

Customers must be able to access banking services when required.

---

## Authenticity

The system must verify users and relevant systems.

---

## Accountability

Sensitive actions should be associated with identifiable users, systems, and timestamps.

---

## Non-Repudiation

Certain transactions may require strong evidence regarding their origin and integrity.

---

## Attack Surface

Potential attack surfaces include:

* Web application
* Mobile application
* APIs
* Employee endpoints
* Cloud infrastructure
* Third-party integrations
* Identity infrastructure

---

# 43. Security Design Checklist

When analyzing a system, ask:

1. What assets require protection?
2. What is the business impact if an asset is compromised?
3. Who should have access?
4. How are identities authenticated?
5. How is authorization enforced?
6. What information requires confidentiality?
7. How is integrity protected?
8. How is availability maintained?
9. How are actions logged?
10. Can attackers modify logs?
11. How is time synchronized?
12. What are the trust boundaries?
13. What is the attack surface?
14. Which interfaces are unnecessarily exposed?
15. What happens when a control fails?
16. How are backups protected?
17. How is residual risk evaluated?
18. Who owns each risk?
19. How are incidents detected?
20. How is recovery performed?

---

# 44. Safe Cybersecurity Laboratory

Recommended learning environment:

```text
Windows Host
     |
     +---- VS Code
     |
     +---- Python
     |
     +---- Kali Linux VM
```

Use isolated laboratory systems and intentionally vulnerable educational targets where appropriate.

Foundation exercises:

1. Learn Linux users and groups.
2. Learn Linux permissions.
3. Study Windows users and groups.
4. Inspect local security logs.
5. Understand firewall concepts.
6. Build a local Python application.
7. Add authentication.
8. Add authorization.
9. Add audit logging.
10. Create a risk model.
11. Draw an attack-surface diagram.
12. Identify trust boundaries.
13. Design defense-in-depth controls.
14. Evaluate residual risk.

Only assess systems that you own or have explicit authorization to test.

---

# 45. The Complete Mental Model

The most useful conceptual chain from this lesson is:

```text
                    ASSET
                      |
                      v
                   THREAT
                      |
                      v
                VULNERABILITY
                      |
                      v
                 LIKELIHOOD
                      |
                      +
                      |
                    IMPACT
                      |
                      v
                    RISK
                      |
                      v
                   CONTROL
                      |
                      v
               RESIDUAL RISK
```

The security objectives surrounding this model are:

```text
CIA
 |
 +-- Confidentiality
 |
 +-- Integrity
 |
 +-- Availability
```

Identity and evidence concepts surround it:

```text
Identity
 |
 +-- Identification
 +-- Authentication
 +-- Authorization
 +-- Accountability
 +-- Non-repudiation
```

Architecture principles surround the controls:

```text
Least Privilege
Defense in Depth
Zero Trust
Secure by Design
Secure by Default
Fail Secure
Separation of Duties
Attack Surface Reduction
```

---

# 46. What I Learned

After completing this lesson, I should be able to explain:

* What cybersecurity is
* What an asset is
* What a threat is
* What a vulnerability is
* What risk is
* The CIA triad
* Confidentiality
* Integrity
* Availability
* Authenticity
* Authentication
* Authorization
* Accountability
* Non-repudiation
* Least privilege
* Need to know
* Defense in depth
* Zero Trust
* Secure by design
* Secure by default
* Fail-secure behavior
* Separation of duties
* Complete mediation
* Security controls
* Preventive controls
* Detective controls
* Corrective controls
* Recovery controls
* Compensating controls
* Attack surface
* Attack-surface reduction
* Risk matrices
* Risk treatment
* Residual risk
* Threat modeling
* STRIDE
* Security logging
* Windows security fundamentals
* Kali Linux fundamentals
* Cryptographic hashes
* HMAC
* Security architecture

---

# 47. Key Distinctions to Memorize

```text
Threat
= Potential source of harm

Vulnerability
= Weakness

Risk
= Potential loss/harm associated with a threat exploiting weakness

Authentication
= Who are you?

Authorization
= What can you do?

Accountability
= What did you do and can the action be associated with you?

Non-repudiation
= What evidence supports that the action/message originated from you?

Confidentiality
= Prevent unauthorized disclosure

Integrity
= Prevent/detect unauthorized modification

Availability
= Keep authorized services accessible

Attack Surface
= Exposed points through which a system could potentially be attacked
```

---

# 48. Foundation-to-Advanced Roadmap

These foundations lead naturally into:

```text
Cybersecurity Foundations
        |
        v
Networking Fundamentals
        |
        v
Network Security
        |
        v
Operating System Security
        |
        v
Cryptography
        |
        v
Web/Application Security
        |
        v
Identity & Access Management
        |
        v
Security Operations
        |
        v
Threat Detection
        |
        v
Incident Response
        |
        v
Digital Forensics
        |
        v
Cloud Security
        |
        v
DevSecOps
        |
        v
Penetration Testing
        |
        v
Red Team / Blue Team
        |
        v
Security Architecture
        |
        v
Advanced Cybersecurity Engineering
```

The most important lesson is that cybersecurity is not a collection of isolated tools.

It is a way of reasoning about **assets, threats, vulnerabilities, risk, controls, evidence, trust, and resilience**.

That mental model becomes the foundation for every advanced cybersecurity specialization that follows.

