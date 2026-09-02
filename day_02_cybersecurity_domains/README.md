# Cybersecurity Domains

## Introduction

Cybersecurity is the practice of protecting information systems, networks, applications, devices, identities, cloud environments and data from unauthorized access, misuse, disruption, modification and destruction.

The subject is broad because modern organizations do not operate from a single security boundary. A typical environment can contain employee computers, servers, networks, cloud platforms, web applications, databases, identity systems and third-party services. Each component introduces different security requirements.

The Python study program covers seven major cybersecurity domains:

1. Network Security
2. Endpoint Security
3. Application Security
4. Cloud Security
5. Identity Security
6. Data Security
7. Security Operations

It also explains the role of **Kali Linux** and **Windows** within cybersecurity.

---

# 1. Cybersecurity Fundamentals

The foundation of cybersecurity is commonly understood through the **CIA Triad**:

* **Confidentiality** means information should only be available to authorized users and systems.
* **Integrity** means information should remain accurate and protected from unauthorized modification.
* **Availability** means systems and information should remain accessible when legitimate users need them.

These three properties are interconnected. A security control can improve one property while affecting another, so security decisions must consider business requirements, usability, performance and risk.

Cybersecurity is not simply about preventing attacks. It also includes preparing for incidents, detecting suspicious behavior, limiting damage, recovering systems and improving security controls.

---

# 2. Network Security

Network security protects communication infrastructure and the traffic moving through it.

The major concepts covered include:

* IP addresses
* MAC addresses
* Ports
* Protocols
* TCP
* UDP
* DNS
* DHCP
* Routers
* Switches
* Firewalls
* VPNs
* Network segmentation
* Network monitoring
* Zero Trust

The OSI model provides a useful way of understanding where different technologies and security controls operate.

Network security is important because systems communicate with one another constantly. If communication is unrestricted, compromise of one system can potentially expose many other systems.

A firewall can control traffic based on characteristics such as source, destination, protocol and port. A secure architecture normally avoids allowing unnecessary communication.

---

# 3. Network Segmentation

Network segmentation divides an environment into different security zones.

A simple architecture can contain:

* Internet
* Firewall
* DMZ
* Application network
* Database network
* Management network

The purpose is to limit unnecessary communication and reduce the impact of a compromised system.

If an internet-facing application server is compromised, it should not automatically have unrestricted access to employee computers, administrative systems or databases.

Segmentation therefore supports the principle of reducing the **blast radius** of an incident.

---

# 4. Zero Trust

Zero Trust is an approach in which network location alone is not treated as proof of trust.

Instead, access decisions can consider:

* Identity
* Device
* Resource
* Application
* Context
* Policy
* Risk

The basic idea is to verify access explicitly, use least privilege and continuously evaluate security conditions.

An employee being connected to an internal network does not automatically mean that every internal resource should be accessible to that employee.

---

# 5. Endpoint Security

Endpoint security protects computers and other devices that connect to an environment.

Examples include:

* Windows laptops
* Windows desktops
* Linux servers
* Virtual machines
* Mobile devices
* Enterprise servers

Important endpoint security controls include:

* Security updates
* Endpoint protection
* Host firewalls
* Disk encryption
* Least privilege
* Application control
* Security logging
* Service management
* Configuration hardening

Endpoint security is especially important because endpoints are frequently used by people and applications. A compromised endpoint can become a starting point for unauthorized access to other resources.

---

# 6. Windows Security

Windows is heavily used in enterprise environments, making Windows security an important part of cybersecurity.

Important Windows security concepts include:

* Windows Defender
* Windows Firewall
* User Account Control
* Windows Event Logs
* PowerShell
* Active Directory
* Group Policy
* NTFS permissions
* BitLocker
* Windows services
* Scheduled tasks
* Credential protection

Security professionals frequently investigate Windows authentication events, process creation, services, user accounts, privilege changes and network activity.

Windows Event IDs can provide useful evidence during investigations.

Examples include:

* `4624` for successful logon
* `4625` for failed logon
* `4688` for process creation when appropriate auditing is enabled
* `4720` for user account creation
* `4728` for certain group membership changes
* `4732` for certain local security group membership changes
* `7045` for service installation

An individual event rarely proves malicious activity by itself. Analysts normally consider the time, source, account, device, frequency and surrounding events.

---

# 7. Linux Security

Linux security involves several fundamental concepts:

* Users
* Groups
* File permissions
* Ownership
* Processes
* Services
* SSH
* System logs
* Package management
* Firewall configuration
* Kernel security
* `sudo`
* Mandatory access controls

Linux file permissions such as:

`rwxr-xr--`

represent different permissions for the owner, group and other users.

Understanding Linux administration is particularly useful when working with servers, cloud infrastructure, security tools and security operations.

---

# 8. Kali Linux

Kali Linux is a Debian-based Linux distribution designed for security testing, security research, digital forensics and related professional activities.

It is not itself a security methodology. It is an operating system containing many tools used by security professionals.

Common tools and their general purposes include:

| Tool            | Purpose                                           |
| --------------- | ------------------------------------------------- |
| Wireshark       | Network protocol analysis                         |
| Nmap            | Network discovery and security auditing           |
| Burp Suite      | Web application security testing                  |
| Nikto           | Web server assessment                             |
| John the Ripper | Password security auditing                        |
| Hydra           | Authentication testing in authorized environments |
| Metasploit      | Security testing and vulnerability validation     |
| Autopsy         | Digital forensics                                 |
| tcpdump         | Command-line packet capture and analysis          |

The important concept is that these tools should be used only within authorized environments.

For example, Nmap can help a security professional understand which services are exposed by a system under assessment. Wireshark can help analyze network communication. Burp Suite can help inspect web application requests and responses.

Kali therefore fits into multiple cybersecurity domains rather than belonging to one domain only.

---

# 9. Application Security

Application security protects software throughout its lifecycle.

The lifecycle includes:

* Requirements
* Architecture
* Design
* Development
* Testing
* Deployment
* Monitoring
* Maintenance

Security should be considered during design instead of being treated as a final testing activity.

Important application security concepts include:

* Authentication
* Authorization
* Input validation
* Output encoding
* Secure session management
* Secure database access
* Cryptography
* Dependency security
* Secure configuration
* Logging
* Monitoring
* Secure software design

Common classes of application weaknesses include broken access control, authentication weaknesses, injection, cross-site scripting, security misconfiguration, cryptographic failures and insecure dependency usage.

---

# 10. Authentication and Authorization

Authentication and authorization solve different problems.

**Authentication** establishes who an identity is.

**Authorization** determines what that identity is allowed to do.

For example, successfully logging into a banking application proves the identity of the user. It does not automatically mean the user can access every account or perform every administrative operation.

A secure application must enforce authorization independently of authentication.

---

# 11. Secure Software Design

Several principles are important in secure application design.

### Least Privilege

Give users and systems only the permissions required for their tasks.

### Defense in Depth

Use multiple layers of protection instead of relying on a single security control.

### Secure Defaults

Systems should begin with safer configurations rather than requiring administrators to discover every security setting manually.

### Separation of Duties

Important operations can be divided among different roles so that one identity does not have unnecessary control over an entire process.

### Minimize Attack Surface

Remove unnecessary services, features, interfaces and permissions.

---

# 12. Cloud Security

Cloud security protects cloud infrastructure, services, workloads, identities, configurations and data.

Cloud service models include:

* Infrastructure as a Service
* Platform as a Service
* Software as a Service

Cloud environments introduce security challenges because infrastructure can be created and changed quickly.

Important cloud security controls include:

* Identity and Access Management
* Multi-factor authentication
* Least-privilege permissions
* Security groups
* Network segmentation
* Encryption
* Key management
* Secrets management
* Logging
* Configuration monitoring
* Vulnerability management
* Backup and recovery

---

# 13. Shared Responsibility

Cloud security follows a shared responsibility model.

The cloud provider and customer have different security responsibilities depending on the service being used.

Customer responsibilities can include:

* Identity configuration
* Permissions
* Data
* Application configuration
* Secrets
* Network rules
* Virtual machine security
* Logging configuration

The exact responsibility depends on whether the service is IaaS, PaaS or SaaS.

A major cloud security mistake is assuming that moving a system to the cloud automatically transfers all security responsibility to the provider.

---

# 14. Identity Security

Identity security protects accounts, credentials, authentication systems and access permissions.

Important concepts include:

* Identity
* Authentication
* Authorization
* Credentials
* Roles
* Privileges
* Multi-factor authentication
* Single sign-on
* Identity and Access Management
* Privileged Access Management

Identity has become a major security boundary because users can access resources from different networks, devices and locations.

---

# 15. Multi-Factor Authentication

Authentication factors are commonly divided into:

### Something You Know

Examples:

* Password
* PIN

### Something You Have

Examples:

* Security key
* Authenticator device

### Something You Are

Examples:

* Biometric characteristic

Multi-factor authentication improves security by requiring independent factors rather than simply requiring multiple pieces of information from the same category.

---

# 16. Least Privilege and Privileged Access

Least privilege means giving an identity only the access required to perform its legitimate responsibilities.

An employee who only needs to read a report does not need system administrator privileges.

Privileged accounts deserve stronger controls because they can affect large numbers of systems.

Examples include:

* Domain administrators
* Cloud administrators
* Database administrators
* Infrastructure administrators
* Security administrators

Privileged Access Management can include:

* Just-in-time access
* Approval workflows
* MFA
* Separate administrative accounts
* Credential rotation
* Session monitoring
* Detailed logging

---

# 17. Data Security

Data security protects information throughout its lifecycle.

Data can exist as:

* Data at rest
* Data in transit
* Data in use

Data at rest can include databases, files, hard drives, cloud storage and backups.

Data in transit occurs when information moves between systems.

Data security controls include:

* Encryption
* Access control
* Data classification
* Data loss prevention
* Database permissions
* Key management
* Backup protection
* Secure deletion

---

# 18. Data Classification

Data classification helps determine how strongly information should be protected.

A simple classification model contains:

### Public

Information intended for public distribution.

### Internal

Information intended primarily for organizational use.

### Confidential

Information where unauthorized disclosure could cause harm.

### Restricted

Highly sensitive information requiring strict access controls.

Classification allows organizations to apply controls according to the sensitivity and business importance of information.

---

# 19. Cryptography

Cryptography is a major cross-domain security technology.

It supports:

* Confidentiality
* Integrity
* Authentication
* Protection of communications
* Secure storage

Symmetric encryption generally uses a secret key for encryption and decryption.

Asymmetric cryptography uses a public and private key pair.

Hashing is different from encryption. A cryptographic hash produces a fixed-size digest and is designed to be computationally difficult to reverse.

Passwords should not normally be stored as simple unsalted hashes. Specialized password hashing mechanisms are used to make password cracking more difficult.

---

# 20. Security Operations

Security Operations is responsible for continuously monitoring, detecting, investigating and responding to security events.

Security operations activities include:

* Monitoring
* Detection
* Alert triage
* Investigation
* Threat analysis
* Incident response
* Threat hunting
* Vulnerability management
* Detection engineering
* Security automation
* Reporting

Security Operations Centers can contain analysts with different levels of responsibility, from initial alert monitoring to advanced investigations.

---

# 21. SIEM

A Security Information and Event Management platform collects and correlates security-related events.

Potential log sources include:

* Windows Event Logs
* Linux logs
* Firewall logs
* VPN logs
* Identity provider logs
* Cloud logs
* Application logs
* Endpoint security telemetry
* DNS logs

SIEM systems allow security teams to connect events from different parts of an environment.

For example, a suspicious login can be correlated with endpoint activity and unusual network communication.

---

# 22. Log Analysis

Log analysis is one of the most important practical security skills.

The Python script demonstrates simple authentication log analysis by identifying failed login events.

A failed login does not automatically indicate an attack.

Security analysts need to examine:

* Number of attempts
* Source address
* Target account
* Time
* Device
* Successful login afterward
* Historical behavior
* MFA activity
* Other related events

Security analysis therefore involves context rather than simply counting events.

---

# 23. Risk Management

A simplified risk model is:

**Risk = Likelihood × Impact**

For example:

* Likelihood = 4
* Impact = 5
* Risk = 20

This is a simplified conceptual model. Real risk assessment can use more detailed methodologies.

Risk can be handled through:

* Avoidance
* Reduction
* Transfer
* Acceptance

Security does not require eliminating every possible risk. It requires understanding risk and applying controls appropriate to business requirements and potential impact.

---

# 24. Vulnerability Management

Vulnerability management is a continuous process.

A typical process is:

1. Asset discovery
2. Vulnerability identification
3. Risk assessment
4. Prioritization
5. Remediation
6. Validation
7. Continuous monitoring

A vulnerability's technical severity is not necessarily the same as its business risk.

A moderate vulnerability affecting a critical internet-facing system may deserve more attention than a high-severity vulnerability affecting an isolated laboratory system.

Context matters.

---

# 25. Incident Response

Incident response is the organized process used to handle security incidents.

A common lifecycle is:

1. Preparation
2. Detection and analysis
3. Containment
4. Eradication
5. Recovery
6. Lessons and improvement

Preparation includes:

* Policies
* Tools
* Access
* Backups
* Logging
* Communication procedures
* Response playbooks

During an investigation, security teams try to determine:

* What happened?
* When did it happen?
* Which systems were affected?
* Which identities were involved?
* What data was affected?
* What was the initial entry point?
* Is the activity continuing?
* What evidence exists?

---

# 26. Threat Modeling

Threat modeling is used to identify security problems before they become incidents.

A basic process includes:

1. Identify assets
2. Identify trust boundaries
3. Identify entry points
4. Identify threats
5. Estimate risk
6. Design controls
7. Validate controls

For a web application, important assets may include customer accounts, payment information and business data.

Entry points may include:

* Web applications
* APIs
* Mobile applications
* Administrative interfaces
* Third-party integrations

Threat modeling helps security become part of architecture rather than an afterthought.

---

# 27. Defense in Depth

Defense in depth means using multiple layers of security.

A simplified architecture may contain:

* Firewall
* Network controls
* Application security
* Authentication
* Authorization
* Database controls
* Encryption
* Logging
* Security monitoring

If one control fails, another control may still reduce the impact.

This is particularly important because no individual security control is perfect.

---

# 28. Security Architecture

The cybersecurity domains are interconnected.

When a user accesses a cloud application:

**Identity Security** verifies the identity.

**Endpoint Security** protects and evaluates the device.

**Network Security** protects communication.

**Application Security** protects the software.

**Cloud Security** protects cloud resources and configurations.

**Data Security** protects the information.

**Security Operations** monitors activity across the environment.

This means cybersecurity should be understood as an interconnected system rather than seven completely separate subjects.

---

# 29. Security Automation

Security automation can reduce repetitive manual work.

Examples include:

* Collecting logs
* Enriching alerts
* Creating tickets
* Checking configurations
* Notifying analysts
* Generating reports
* Performing predefined administrative actions

Automation must be designed carefully.

An incorrect detection combined with an automatic response can cause operational problems. Therefore security automation should consider confidence, authorization, business impact, auditability and rollback.

---

# 30. Threat Hunting

Threat hunting is the proactive search for suspicious activity.

Instead of waiting for an alert, an analyst can begin with a hypothesis.

For example:

> Could unusual administrative login behavior exist in the environment?

The analyst can then investigate:

* Authentication logs
* Endpoint activity
* Network connections
* Privilege changes
* Cloud activity

Threat hunting requires understanding normal behavior so that unusual behavior can be identified.

---

# 31. Detection Engineering

Detection engineering converts security knowledge into repeatable detection rules.

A detection normally considers:

* Data source
* Signal
* Detection logic
* Expected behavior
* False positives
* Severity
* Response
* Testing
* Maintenance

An example conceptual rule could identify multiple authentication failures followed by a successful login from an unusual source.

The rule itself does not prove compromise. It creates a signal that can be investigated.

---

# 32. False Positives and False Negatives

A **false positive** occurs when legitimate behavior is classified as malicious.

A **false negative** occurs when malicious behavior is not detected.

Security operations must manage both.

Too many false positives can overwhelm analysts and cause important alerts to be ignored.

Too many false negatives allow malicious activity to remain undetected.

Effective security monitoring therefore requires useful telemetry, good detection logic and continuous tuning.

---

# 33. Security Metrics

Important security metrics include:

### MTTD

Mean Time to Detect.

It measures how long it takes, on average, to detect an incident or suspicious activity.

### MTTR

Mean Time to Respond or Recover, depending on the organization's definition.

### False Positive Rate

Measures how frequently alerts are incorrectly classified as malicious.

### Patch Compliance

Measures how many relevant systems meet defined patching requirements.

### MFA Coverage

Measures how many relevant identities are protected by multi-factor authentication.

Metrics allow security teams to measure security performance rather than relying only on subjective judgments.

---

# 34. Security Configuration and Hardening

Secure configuration reduces unnecessary exposure.

Important areas include:

* Unnecessary services
* User permissions
* Firewall configuration
* Authentication
* Encryption
* Logging
* Software versions
* Administrative interfaces
* Security policies

Configuration drift occurs when systems gradually move away from their approved security configuration.

Continuous monitoring helps identify this drift.

A security baseline provides a defined minimum configuration standard for a system.

---

# 35. Asset Management

Asset management is fundamental to cybersecurity.

An organization should understand what systems it owns or operates.

An asset inventory can include:

* Hostname
* IP address
* Operating system
* Owner
* Business purpose
* Criticality
* Installed software
* Data classification
* Security status

Unknown assets create security blind spots.

Asset management supports vulnerability management, incident response, patch management and risk assessment.

---

# 36. Security Testing

Security testing validates whether security controls actually work.

Methods include:

* Vulnerability scanning
* Configuration assessment
* Code review
* Penetration testing
* Security testing
* Architecture review
* Threat modeling
* Log review
* Tabletop exercises
* Disaster recovery testing

Security testing requires defined scope and authorization.

A professional security assessment should clearly establish which systems can be tested and what activities are permitted.

---

# 37. DevSecOps

DevSecOps integrates security into software development and operations.

Instead of treating security as a final review, security becomes part of the development lifecycle.

Security activities can include:

* Dependency scanning
* Secret detection
* Static analysis
* Dynamic testing
* Container scanning
* Infrastructure-as-code scanning
* Code review
* Security testing
* Runtime monitoring

The goal is to identify security weaknesses earlier and continuously rather than waiting until the end of development.

---

# 38. Software Supply Chain Security

Modern applications depend on many external components.

Examples include:

* Libraries
* Packages
* Containers
* Operating systems
* Third-party APIs
* Cloud services
* Build systems

A vulnerability or compromise in a dependency can affect applications that depend on it.

Supply chain security therefore considers:

* Dependency inventories
* Package provenance
* Software integrity
* Secure build systems
* Signing
* Dependency vulnerability monitoring
* Vendor security
* CI/CD security

---

# 39. Security Telemetry

Telemetry is information collected about system behavior.

Endpoint telemetry can include:

* Process creation
* File activity
* Registry changes
* Network connections

Network telemetry can include:

* DNS queries
* Firewall events
* Connection information
* Proxy events

Identity telemetry can include:

* Login events
* MFA activity
* Privilege changes
* Password changes

Cloud telemetry can include:

* API calls
* Resource changes
* Authentication activity

Application telemetry can include:

* Requests
* Errors
* Authentication
* Authorization decisions

Effective detection depends on having useful telemetry.

---

# 40. Business Continuity and Recovery

Cybersecurity is also concerned with resilience.

Important concepts include:

### Business Continuity

The ability to continue important business functions during disruption.

### Disaster Recovery

The ability to restore systems after a disruptive event.

### Recovery Point Objective

The acceptable amount of data loss, measured in time.

### Recovery Time Objective

The acceptable amount of downtime before a service should be restored.

Security incidents can affect confidentiality, integrity and availability, so recovery is an important part of cybersecurity.

---

# 41. Security Governance

Technical controls operate within organizational policies and governance.

Security policies can cover:

* Access control
* Authentication
* Acceptable use
* Data classification
* Encryption
* Vulnerability management
* Incident response
* Backup
* Cloud security
* Endpoint security
* Vendor security
* Security awareness

Governance establishes expectations.

Technical controls enforce those expectations.

---

# 42. Security Maturity

Security maturity can be understood as a progression.

A less mature environment may be primarily reactive.

A more mature environment has:

* Documented processes
* Defined controls
* Security metrics
* Continuous monitoring
* Automated processes
* Risk-based decision making
* Continuous improvement

Security maturity is not simply about purchasing more security products.

An organization can own many security tools and still have weak security if alerts are ignored, vulnerabilities remain unresolved, permissions are excessive or critical assets are unknown.

---

# 43. Attack Surface

The attack surface is the collection of exposed points through which a system could potentially be interacted with or affected.

Examples include:

* Internet-facing applications
* Network services
* APIs
* User accounts
* Cloud resources
* Remote administration interfaces
* Endpoints
* Third-party integrations
* Software dependencies

Attack surface management involves discovering assets, understanding exposure, identifying weaknesses and reducing unnecessary exposure.

---

# 44. Cross-Domain Security

The seven cybersecurity domains are strongly connected.

A compromised identity can affect an endpoint.

A compromised endpoint can create network security problems.

A vulnerable application can expose sensitive data.

A cloud misconfiguration can expose identities and storage.

Weak logging can prevent Security Operations from detecting an incident.

A network control can reduce application exposure.

Encryption can protect data even if network traffic is intercepted.

This interdependence is why security architecture must consider the complete environment.

---

# 45. Kali Linux and Windows Together

Kali Linux and Windows have different roles in cybersecurity.

Windows is commonly found in enterprise environments and is therefore frequently protected, monitored, investigated and administered by security teams.

Kali Linux is specialized for security assessment, research, testing and forensics.

A security professional may therefore work with both:

* Windows for endpoint security and enterprise administration
* Kali Linux for authorized security testing
* Linux servers for infrastructure
* Network devices for network security
* Cloud platforms for cloud security
* SIEM platforms for Security Operations

Understanding both operating systems provides a broader view of how enterprise systems are built and protected.

---

# 46. Professional Security Principles

The major principles reinforced by the study program are:

* Least privilege
* Defense in depth
* Secure by design
* Secure defaults
* Separation of duties
* Minimize attack surface
* Strong authentication
* Explicit authorization
* Continuous monitoring
* Assume breach
* Data minimization
* Accountability
* Resilience
* Recovery
* Continuous improvement

These principles apply across multiple cybersecurity domains.

---

# 47. Authorization and Ethics

Cybersecurity tools can interact deeply with systems.

The same technical knowledge can be used for defensive security testing or unauthorized activity.

Professional security work requires clear authorization and defined scope.

Before conducting security testing, professionals need to understand:

* Which systems are in scope
* Who authorized the activity
* Which techniques are permitted
* When testing can occur
* Operational restrictions
* Data handling requirements
* Reporting requirements

Technical capability alone does not make an activity legitimate.

Authorization, scope and professional responsibility are fundamental parts of cybersecurity practice.

