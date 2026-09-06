# Security Architecture

## 1. Topic Introduction

Security architecture is the structured design of people, processes, technologies, controls, trust boundaries, identities, networks, applications, data stores, and operational mechanisms that protect an information system.

A secure architecture does not depend on a single security product. It establishes multiple control layers so that the compromise or failure of one control does not automatically result in complete system compromise.

This study script demonstrates six foundational architectural principles:

- Defense in depth
- Least privilege
- Security segmentation
- Zero trust
- Secure defaults
- Fail-safe design

It also connects those principles to authentication, authorization, identity, network security, workload identity, API security, encryption, logging, monitoring, threat modeling, configuration management, microsegmentation, incident response, and diagrams.net architecture visualization.

The implementation is deliberately self-contained and uses only Python's standard library.

---

## 2. Security Architecture as a System

A security architecture can be viewed as a set of interacting layers:

1. Identity
2. Authentication
3. Authorization
4. Network security
5. Application security
6. Data protection
7. Monitoring and detection
8. Incident response
9. Configuration and governance

The objective is not simply to prevent every possible attack. A realistic architecture should:

- reduce the probability of unauthorized access;
- reduce the blast radius of successful compromise;
- make unauthorized activity detectable;
- prevent privilege escalation;
- constrain lateral movement;
- protect sensitive data;
- fail safely;
- support recovery;
- remain manageable as the environment changes.

The script models these properties through executable policies rather than presenting them only as abstract definitions.

---

# 3. Defense in Depth

Defense in depth means using multiple security controls at different architectural layers.

For example, a database may be protected by:

- authentication;
- MFA;
- role-based authorization;
- network segmentation;
- workload identity;
- database permissions;
- encryption;
- monitoring;
- audit logging;
- incident response.

The important property is that a failure in one control should not automatically remove every other protection.

## Example

An attacker may obtain a valid password. MFA can prevent account takeover.

If MFA is bypassed or a session is compromised, least privilege can restrict the account.

If an application account is compromised, network segmentation can prevent arbitrary access to other systems.

If network controls are misconfigured, database authorization can still reject unauthorized operations.

If preventive controls fail, monitoring can provide detection and response opportunities.

This layered approach is more resilient than relying on one perimeter firewall or one authentication mechanism.

---

# 4. Least Privilege

Least privilege means providing a subject with only the permissions necessary to perform its legitimate responsibilities.

The subject may be:

- a human user;
- an administrator;
- an application;
- a microservice;
- a scheduled job;
- an automation identity;
- a database account.

The script represents permissions using roles.

For example:

- `reader` can read documents;
- `analyst` can read documents and reports;
- `developer` can read logs and deploy applications;
- `database_admin` can perform database operations;
- `security_admin` can operate security functions.

An analyst does not receive database write permissions simply because the analyst has successfully authenticated.

## Why Least Privilege Matters

Excessive privilege increases blast radius.

If an account with one required permission is compromised, the attacker may have access to only one capability.

If every account has administrative privileges, compromise of one account can expose an entire environment.

Least privilege therefore contributes directly to:

- reduced lateral movement;
- reduced privilege escalation;
- reduced accidental modification;
- reduced impact of credential compromise;
- stronger separation of duties.

## Least Privilege for Workloads

Least privilege applies to services as well as users.

The script defines a `ServiceIdentity` in which a service is explicitly restricted to:

- permitted target services;
- permitted actions.

For example, a payment service may communicate with a ledger service but not with arbitrary internal services.

This is an important cloud-native security principle because microservices frequently communicate across network boundaries.

---

# 5. Authentication and Authorization

Authentication and authorization are different security functions.

## Authentication

Authentication answers:

> Who or what is making the request?

Examples include:

- passwords;
- hardware security keys;
- certificates;
- biometrics;
- device credentials;
- federated identity.

## Authorization

Authorization answers:

> Is this authenticated identity permitted to perform this action against this resource?

A valid identity may still be denied.

The script demonstrates this distinction by authenticating users first and then evaluating explicit permissions.

A database administrator and an ordinary analyst can both authenticate successfully while receiving different authorization decisions.

---

# 6. Authentication Factors

The script distinguishes several factor categories.

## Knowledge

Something the subject knows.

Examples:

- password;
- PIN.

## Possession

Something the subject possesses.

Examples:

- hardware security key;
- registered authenticator;
- device credential.

## Inherence

Something associated with the subject's biological characteristics.

Examples:

- fingerprint;
- facial biometric.

## Context

Environmental or contextual evidence.

Examples:

- device posture;
- risk score;
- time;
- network characteristics;
- behavioral signals.

MFA is strongest when independent factors are combined rather than simply requiring two pieces of information that belong to the same factor category.

---

# 7. Role-Based Access Control

Role-Based Access Control, or RBAC, assigns permissions to roles and roles to identities.

The conceptual relationship is:

`User -> Role -> Permission`

The script implements this relationship using a dictionary containing roles and permission sets.

RBAC provides:

- centralized permission definitions;
- easier auditing;
- consistent authorization;
- reduced direct user-to-permission relationships.

A weakness of poorly designed RBAC systems is role explosion. If every small contextual difference creates a new role, administration becomes difficult.

RBAC is therefore often combined with attribute and policy-based decisions.

---

# 8. Attribute-Based Access Control

Attribute-Based Access Control, or ABAC, makes authorization decisions using attributes.

Potential attributes include:

### Subject attributes

- identity;
- department;
- role;
- employment status;
- authentication strength.

### Resource attributes

- classification;
- owner;
- sensitivity;
- data type.

### Environmental attributes

- time;
- device posture;
- location;
- network context;
- risk score.

The script's zero-trust policy approximates ABAC because it considers:

- authentication;
- roles;
- device compliance;
- MFA;
- risk;
- resource sensitivity.

---

# 9. Policy-Based Access Control

A policy engine can combine multiple inputs into one authorization decision.

Conceptually:

`Decision = Policy(Identity, Action, Resource, Device, Context, Risk)`

This is more expressive than relying only on a user's network location or role.

The script's `ZeroTrustPolicy` functions as a simplified policy decision point.

---

# 10. Network Segmentation

Segmentation divides an environment into distinct security zones.

The example architecture contains:

- Internet;
- DMZ;
- Application;
- Database;
- Management;
- Security.

A typical traffic flow is:

`Internet -> DMZ -> Application -> Database`

Each transition represents a security boundary.

The architecture intentionally avoids:

`Internet -> Database`

and avoids unrestricted:

`Application -> Every Internal System`

## Why Segmentation Matters

If an application server is compromised, segmentation can prevent an attacker from directly reaching:

- administrative systems;
- unrelated applications;
- sensitive databases;
- backup systems;
- identity infrastructure.

Segmentation therefore reduces lateral movement.

---

# 11. Default Deny

The segmentation policy implements a default-deny model.

Only explicitly defined traffic is allowed.

For example:

- Internet to DMZ on HTTPS: allowed;
- DMZ to Application on the designated service port: allowed;
- Application to Database on PostgreSQL: allowed;
- arbitrary Internet to Database traffic: denied.

The absence of a rule is itself meaningful.

No rule does not mean:

> probably allowed.

It means:

> denied until explicitly authorized.

This is a foundational secure-default property.

---

# 12. Secure Defaults

Secure defaults mean that a system starts from the safer configuration.

The script models secure defaults through `ServiceConfiguration`.

The secure baseline includes:

- authentication required;
- authorization required;
- encryption required;
- debug disabled;
- public administrative interface disabled;
- anonymous access disabled;
- firewall default deny;
- audit logging enabled;
- secure headers enabled;
- rate limiting enabled.

A secure default reduces the chance that a forgotten configuration option creates a security vulnerability.

## Common Insecure Defaults

Examples include:

- anonymous access enabled;
- administrative interfaces exposed publicly;
- debugging enabled in production;
- password authentication unnecessarily enabled;
- unrestricted network access;
- missing audit logs;
- unencrypted communication.

---

# 13. Fail-Safe Design

Fail-safe design determines what happens when a security dependency fails.

A critical question is:

> What happens if the authorization service is unavailable?

For sensitive authorization, an unsafe implementation might fail open:

`Policy unavailable -> Allow`

A safer design is:

`Policy unavailable -> Deny`

The script implements this behavior in `fail_safe_authorize()`.

## Fail Closed

Fail-closed behavior prevents accidental access when a security control cannot make a valid decision.

This is appropriate for many authorization boundaries.

## Availability Trade-Off

Fail closed can reduce availability.

A mature architecture therefore considers controlled alternatives such as:

- short-lived cached authorization decisions;
- restricted read-only operation;
- emergency break-glass access;
- local policy enforcement;
- bounded degraded modes.

Any fallback must be carefully constrained. A permanent emergency bypass defeats the purpose of the security control.

---

# 14. Zero Trust

Zero trust is based on the principle that network location alone does not establish trust.

A traditional perimeter model often assumes:

`Outside = untrusted`

and:

`Inside = trusted`

Zero trust rejects this binary assumption.

A request can originate from an internal address and still be denied.

The decision can consider:

- authenticated identity;
- authorization;
- MFA;
- device posture;
- resource sensitivity;
- risk;
- requested action;
- contextual conditions.

The script evaluates these properties for every request.

---

# 15. Zero-Trust Components

The script models several conceptual components.

## Policy Enforcement Point

The enforcement point applies the authorization decision.

It sits at or near the access boundary and prevents unauthorized requests from proceeding.

## Policy Decision Point

The decision point evaluates security policy.

It can consider:

- identity;
- resource;
- action;
- device;
- risk;
- context.

## Identity Provider

The identity provider authenticates users and supplies identity information.

## Device Posture Service

The posture service determines whether a device meets security requirements.

Examples of posture signals include:

- encryption enabled;
- endpoint protection active;
- supported operating system;
- current security state;
- organizational enrollment.

## Risk Engine

A risk engine evaluates signals and produces a risk score.

The example uses a simplified numerical model.

Production risk systems are substantially more complex.

---

# 16. Risk-Based Authorization

The script uses three illustrative risk ranges:

- low risk: normal authorization;
- elevated risk: step-up verification;
- very high risk: deny.

For example:

`risk < 50 -> normal evaluation`

`50 <= risk < 80 -> STEP_UP`

`risk >= 80 -> DENY`

These values are educational examples, not universal production thresholds.

Real risk policies require:

- threat intelligence;
- behavioral signals;
- historical activity;
- device signals;
- identity assurance;
- resource sensitivity;
- organizational risk tolerance.

---

# 17. Security Zones

The example architecture uses separate security zones because different systems have different risk profiles.

## Internet

Untrusted external environment.

## DMZ

Contains externally reachable components such as:

- reverse proxies;
- gateways;
- public application endpoints.

## Application Zone

Contains internal application services.

## Database Zone

Contains sensitive persistent data.

## Management Zone

Contains privileged administration paths.

## Security Zone

Contains security control and monitoring capabilities.

Separating these zones reduces the number of paths an attacker can use after compromise.

---

# 18. Trust Boundaries

A trust boundary is a point where security assumptions change.

Important boundaries include:

- Internet to DMZ;
- DMZ to application;
- application to database;
- user to management;
- development to production;
- one tenant to another tenant.

A security architecture should explicitly identify these boundaries.

Each boundary should answer:

1. Who is allowed to cross it?
2. What action is allowed?
3. Which protocol and port are allowed?
4. How is identity established?
5. How is authorization evaluated?
6. How is the crossing logged?
7. What happens if the policy system fails?

---

# 19. Microsegmentation

Traditional segmentation may separate major networks.

Microsegmentation goes further by controlling communication between individual workloads or workload groups.

The script models rules such as:

`orders-api -> orders-db : 5432`

and denies unspecified communication.

This creates a much smaller communication graph.

Microsegmentation is particularly valuable in environments containing many:

- containers;
- virtual machines;
- microservices;
- cloud workloads.

Its major challenge is operational complexity. Policies must accurately reflect legitimate application dependencies.

---

# 20. Workload Identity

Modern architectures require identity for services, not only people.

A service should not automatically trust another service merely because both are inside the same network.

The script models workload identity with:

`ServiceIdentity`

The payment service is allowed to access specific targets using specific actions.

This demonstrates workload-level least privilege.

A compromised service therefore has a narrower blast radius.

---

# 21. API Security

APIs are common architectural trust boundaries.

The script defines endpoints with:

- HTTP method;
- path;
- required permission;
- sensitivity.

Authorization is performed against the endpoint's required permission.

Sensitive endpoints can require stronger authentication such as MFA.

API security should also address:

- authentication;
- authorization;
- input validation;
- rate limiting;
- transport encryption;
- logging;
- error handling;
- abuse prevention;
- object-level authorization;
- service-to-service identity.

Authentication alone does not make an API secure.

---

# 22. Rate Limiting

Rate limiting restricts the number of requests accepted over a period.

The script implements a small fixed-window limiter.

It demonstrates the principle:

`Allowed requests <= configured threshold`

Rate limiting can reduce:

- brute-force attempts;
- request flooding;
- accidental overload;
- some forms of automated abuse.

It is not a replacement for authorization.

## Production Considerations

A production implementation may require:

- distributed state;
- atomic operations;
- reverse-proxy integration;
- per-user limits;
- per-IP limits;
- per-token limits;
- endpoint-specific limits;
- burst handling;
- clock consistency;
- abuse-resistant storage.

---

# 23. Input Validation

Security architecture also includes validating untrusted inputs.

The script demonstrates validation of:

- network ports;
- usernames.

Validation should be explicit and based on expected values or formats.

The port validator rejects:

- non-integers;
- values below 1;
- values above 65535.

The username validator rejects:

- empty values;
- excessively long values;
- unsupported characters.

Validation reduces ambiguity and prevents malformed values from propagating into security-sensitive logic.

---

# 24. Encryption and Data Protection

Data should be considered according to its state.

## Data at Rest

Examples:

- database storage;
- object storage;
- backups;
- disks.

Controls can include encryption and strict access control.

## Data in Transit

Controls include protocols such as TLS.

The objective is to reduce interception and tampering risk.

## Data in Use

Data is exposed while applications process it.

Protection therefore depends on:

- application authorization;
- process isolation;
- workload identity;
- operating-system controls;
- secure memory and execution environments where appropriate.

## Backups

Backups are security-sensitive assets.

They should be protected through:

- encryption;
- access control;
- retention policies;
- isolation;
- integrity mechanisms;
- appropriate immutability.

---

# 25. Logging and Monitoring

Preventive controls are only one part of security architecture.

Detection requires reliable telemetry.

The script uses an `AuditLogger` to record:

- principal;
- action;
- resource;
- decision;
- reason;
- security controls involved.

Security logs can help identify:

- repeated authorization failures;
- suspicious access;
- privilege misuse;
- configuration changes;
- anomalous activity;
- incident timelines.

Logging must be designed carefully because excessive or poorly protected logs can create privacy and security risks.

Sensitive credentials and secrets should not be placed in logs.

---

# 26. Configuration Drift

Security architecture changes over time.

A system can begin securely and become insecure through:

- manual changes;
- deployment changes;
- forgotten firewall rules;
- temporary exceptions;
- infrastructure updates;
- software upgrades.

The script defines a security baseline and compares it with actual configuration.

Example baseline requirements include:

- password-based SSH disabled;
- root login disabled;
- public database access disabled;
- logging enabled;
- encryption enabled.

Configuration drift detection turns a static security architecture into a continuously monitored property.

---

# 27. Secrets Management

Secrets include:

- passwords;
- API keys;
- private keys;
- service credentials;
- database credentials;
- signing secrets.

Important principles include:

- do not hard-code secrets in source code;
- use dedicated secret-management mechanisms;
- use short-lived credentials where practical;
- rotate secrets;
- audit secret access;
- prevent secret exposure through logs;
- separate credentials across environments;
- apply least privilege to secret consumers.

A leaked secret can bypass many other architectural controls, so secret management belongs directly in security architecture.

---

# 28. Cloud Security Architecture

The script represents a layered cloud architecture.

## Edge Layer

Examples:

- WAF;
- DDoS protection;
- TLS termination;
- CDN.

## Identity Layer

Examples:

- SSO;
- MFA;
- workload identity;
- conditional access.

## Network Layer

Examples:

- private networks;
- private subnets;
- security groups;
- network policies.

## Application Layer

Examples:

- secure APIs;
- input validation;
- authorization;
- dependency security.

## Data Layer

Examples:

- encryption;
- key management;
- classification;
- backup protection.

## Operations Layer

Examples:

- logging;
- monitoring;
- configuration compliance;
- incident response.

Cloud architecture does not eliminate the need for traditional security principles. It changes how those principles are implemented.

---

# 29. Threat Modeling

Threat modeling identifies assets, threats, likelihood, impact, and mitigations.

The script represents each threat with:

- name;
- affected asset;
- likelihood;
- impact;
- mitigations.

The illustrative inherent-risk calculation is:

`Risk = Likelihood × Impact`

For example, a threat with likelihood 4 and impact 5 has an illustrative risk score of:

`4 × 5 = 20`

This is a simplified educational model. Real risk methodologies may use more detailed scales and organizational context.

Threat modeling should identify both:

- external threats;
- internal or post-compromise threats.

The latter is important because architecture should limit what happens after an attacker gains an initial foothold.

---

# 30. Attack-Path Analysis

The script creates a directed graph representing possible paths between systems.

For example:

`Internet -> DMZ -> Application -> Database`

A problematic direct path may appear as:

`Internet -> DMZ -> Database`

The second path indicates a potential segmentation weakness.

Attack-path analysis asks:

> If an attacker compromises component A, what can they reach next?

This is closely related to blast-radius analysis.

A strong architecture seeks to minimize unnecessary reachable nodes.

---

# 31. Blast Radius

Blast radius describes the scope of damage after a component or identity is compromised.

Least privilege reduces the permissions available to the compromised identity.

Segmentation reduces reachable systems.

Microsegmentation reduces workload communication.

Strong database authorization reduces data operations.

Together:

`Least privilege + segmentation + workload identity + authorization`

can significantly constrain compromise impact.

---

# 32. Security Architecture Trade-Offs

Security controls have operational costs.

## Strict Segmentation

Benefit:

- reduced lateral movement.

Trade-off:

- increased policy complexity.

## Least Privilege

Benefit:

- reduced blast radius.

Trade-off:

- requires accurate permission design.

## MFA

Benefit:

- stronger resistance to credential compromise.

Trade-off:

- additional authentication friction and dependencies.

## Fail Closed

Benefit:

- prevents unintended access during policy failure.

Trade-off:

- can reduce availability.

## Centralized Policy

Benefit:

- consistent policy management.

Trade-off:

- introduces policy-service dependency and availability considerations.

## Extensive Logging

Benefit:

- improved detection and investigation.

Trade-off:

- storage, processing, privacy, and operational costs.

Security architecture therefore requires balancing confidentiality, integrity, availability, usability, and operational complexity.

---

# 33. Fail-Open Versus Fail-Closed

The correct failure mode depends on the function.

For a sensitive authorization decision:

`Failure -> Deny`

is usually safer.

For a safety-critical or availability-critical service, immediate denial may itself create unacceptable consequences.

A mature architecture therefore defines explicit degraded modes.

Possible patterns include:

- fail closed;
- read-only mode;
- short-lived authorization cache;
- restricted emergency mode;
- break-glass authorization.

The critical requirement is that the fallback is intentional rather than accidental.

---

# 34. Break-Glass Access

Break-glass access provides emergency privileges when normal procedures cannot resolve a critical situation.

The script models break-glass access using:

- requester;
- reason;
- approver;
- expiration time.

A valid request must contain all of these elements and must not be expired.

Emergency privileges should be:

- explicitly requested;
- justified;
- approved;
- time bounded;
- audited;
- reviewed afterward.

Break-glass accounts should not become ordinary administrative accounts.

---

# 35. Common Security Architecture Mistakes

Common failures include:

1. Treating the internal network as automatically trusted.
2. Using a flat network.
3. Giving every service administrative permissions.
4. Confusing authentication with authorization.
5. Using allow-all firewall rules.
6. Exposing databases directly to the Internet.
7. Exposing administrative interfaces publicly.
8. Hard-coding credentials.
9. Leaving debugging enabled in production.
10. Failing open when policy dependencies fail.
11. Keeping emergency privileges permanently enabled.
12. Logging secrets.
13. Assuming one control eliminates a threat.
14. Ignoring east-west traffic.
15. Failing to monitor security controls.
16. Failing to retest security assumptions after architectural changes.

These mistakes generally arise when security is treated as a perimeter feature rather than a property of the complete architecture.

---

# 36. Edge Cases

Security architecture must account for situations where simple rules are insufficient.

## Authenticated but Unauthorized

A valid identity can still be denied.

## Valid Identity with a Compromised Device

Authentication alone may not be sufficient if the endpoint does not meet security requirements.

## Trusted Internal Address

An internal address does not automatically imply trust in a zero-trust architecture.

## Policy Service Failure

Sensitive authorization should not accidentally become permissive.

## Emergency Administration

Emergency access should remain temporary and auditable.

## Stale Authorization Cache

Cached permissions must expire.

## Misconfigured Firewall

The database should retain its own authorization controls even if network controls fail.

## Compromised Application

Workload identity and database permissions should limit what the application can do.

## Logging Failure

Loss of monitoring should not automatically disable preventive authorization controls.

---

# 37. Security Testing

The script contains executable unit tests for security invariants.

Examples include:

- unassigned permissions are denied;
- unknown network paths are denied;
- sensitive operations require MFA;
- authorization dependencies fail safely;
- secure configuration passes validation;
- invalid ports are rejected;
- invalid usernames are rejected;
- unknown microsegmentation paths are denied.

Security tests should verify properties, not only expected successful behavior.

A useful security test asks:

> Can an unauthorized action ever become allowed?

This is often more valuable than testing only legitimate requests.

---

# 38. Randomized Default-Deny Testing

The script also performs randomized policy testing.

It generates combinations of:

- source zones;
- destination zones;
- protocols;
- ports.

For combinations without explicit allow rules, the expected result is DENY.

This demonstrates a valuable security invariant:

`Unknown policy combination -> DENY`

Randomized testing can expose accidental permissive behavior in policy-matching logic.

---

# 39. Performance Considerations

Security controls can introduce latency and resource consumption.

## Central Policy Evaluation

Remote policy decisions can increase request latency.

Caching can reduce latency but introduces:

- stale decisions;
- expiration requirements;
- revocation challenges.

## MFA

MFA adds user interaction and authentication dependencies.

## Deep Inspection

Inspection can consume CPU and memory.

## Logging

Large volumes of telemetry increase:

- network traffic;
- storage;
- ingestion;
- analysis costs.

## Microsegmentation

Microsegmentation increases policy-management complexity and can add control-plane requirements.

## Encryption

Modern systems often handle encryption efficiently, but high-throughput workloads still require capacity planning.

Security should therefore be engineered with performance requirements rather than added blindly after the system is built.

---

# 40. Production Security Considerations

A production security architecture should:

- identify and classify assets;
- document trust boundaries;
- identify all external entry points;
- require authentication where identity matters;
- enforce authorization explicitly;
- apply least privilege;
- isolate sensitive systems;
- control east-west traffic;
- isolate administration;
- protect secrets;
- encrypt sensitive data;
- maintain audit logs;
- monitor security events;
- detect configuration drift;
- maintain secure production defaults;
- define failure behavior;
- provide controlled emergency access;
- test security controls;
- include recovery and incident response.

Security architecture must be continuously maintained because production environments change.

---

# 41. Architecture Maturity

The script describes a simplified maturity progression.

## Level 1: Perimeter-Focused

The primary control is an external firewall.

The internal environment may still be broadly trusted.

## Level 2: Segmented

Major environments are separated.

Sensitive systems receive stronger network boundaries.

## Level 3: Identity-Centric

Users and workloads receive explicit permissions.

## Level 4: Context-Aware

Authorization considers:

- device;
- risk;
- resource sensitivity;
- contextual signals.

## Level 5: Continuously Evaluated

The architecture continuously uses:

- telemetry;
- policy;
- automated detection;
- automated response;
- configuration compliance.

Maturity is not simply the number of security products deployed. It reflects the quality and integration of architectural controls.

---

# 42. Diagrams.net Architecture

The Python script generates a file named:

`security_architecture.drawio`

The generated diagram represents the following logical architecture:

`Internet -> WAF/API Gateway -> DMZ -> Application -> Database`

Supporting components include:

- Identity Provider;
- MFA;
- Policy Decision Point;
- risk evaluation;
- security monitoring;
- management zone;
- segmentation controls.

The diagram intentionally shows the database behind the application layer rather than directly exposing it to the Internet.

It also illustrates explicit administrative paths and security telemetry.

The XML is generated directly by Python, so the diagram is represented as a structured diagrams.net document rather than as an image.

---

# 43. Diagram Interpretation

The diagram can be read from left to right.

## Internet

Represents an untrusted external environment.

## WAF/API Gateway

Provides an initial application-facing security boundary.

Typical controls include:

- TLS;
- request filtering;
- rate limiting;
- API policy enforcement.

## DMZ

Provides isolation for externally reachable components.

## Application Zone

Contains internal application services.

## Database Zone

Contains sensitive persistent information and should have much narrower access.

## Identity Provider

Provides identity information used in authorization.

## Policy Decision Point

Combines identity and context into authorization decisions.

## Security Monitoring

Receives audit telemetry from important components.

## Management Zone

Provides restricted administrative access.

## Security Controls

Represents segmentation, baselines, and other architectural enforcement mechanisms.

---

# 44. Integrated Request Flow

The script's `SecurityArchitecture` class combines several controls into one request flow.

A request follows approximately this sequence:

1. Identify the resource.
2. Determine the source security zone.
3. Evaluate network segmentation.
4. Deny if network access is not explicitly allowed.
5. Authenticate the principal.
6. Validate the request context.
7. Evaluate least privilege.
8. Evaluate device posture.
9. Require MFA for sufficiently sensitive resources.
10. evaluate risk.
11. Return ALLOW, DENY, or STEP_UP.
12. Record the security decision.

This demonstrates defense in depth because no single control determines the entire security outcome.

---

# 45. Security Decision Outcomes

The script uses three outcomes.

## ALLOW

All required controls have passed.

## DENY

The request violates a security requirement.

Examples:

- unauthenticated identity;
- missing permission;
- noncompliant device;
- excessive risk;
- disallowed network path.

## STEP_UP

The request may be legitimate but requires stronger verification.

The primary example is sensitive access without MFA.

This is useful for risk-adaptive authorization because not every request has to be treated as permanently allowed or permanently denied.

---

# 46. Secure Architecture Principles in Combination

The principles are strongest when combined.

Consider an application accessing a database.

### Segmentation

Only the application network can reach the database port.

### Workload Identity

The application identifies itself as a specific workload.

### Least Privilege

The workload receives only required database permissions.

### Zero Trust

The request is evaluated using identity and context rather than network location alone.

### Secure Defaults

Unspecified database access is denied.

### Fail-Safe

If the authorization mechanism fails, sensitive access is not automatically granted.

### Defense in Depth

Encryption, logging, database controls, and monitoring provide additional protection.

This creates a layered architecture rather than a single point of security dependence.

---

# 47. Important Distinctions

| Concept | Primary Question |
|---|---|
| Authentication | Who are you? |
| Authorization | What are you allowed to do? |
| Least privilege | How much permission should you receive? |
| Segmentation | Which systems can communicate? |
| Microsegmentation | Which specific workloads can communicate? |
| Zero trust | Why should this request be trusted right now? |
| Defense in depth | What other controls remain if one fails? |
| Secure defaults | What happens before explicit configuration? |
| Fail-safe design | What happens when a security dependency fails? |
| Monitoring | How will unauthorized activity be detected? |
| Threat modeling | What can go wrong and how can it be reduced? |
| Configuration baseline | What should the system securely look like? |

---

# 48. Relationship Between the Principles

A useful conceptual model is:

`Identity`
    
`-> Authentication`
    
`-> Authorization`
    
`-> Least Privilege`
    
`-> Segmentation`
    
`-> Resource Protection`
    
`-> Monitoring`
    
`-> Detection and Response`

Zero trust overlays this flow by continuously evaluating context.

Defense in depth connects all of the layers.

Secure defaults establish safe starting conditions.

Fail-safe design defines the behavior when controls or dependencies malfunction.

---

# 49. Practical Security Architecture Checklist

The script provides an executable checklist covering:

- asset identification;
- trust boundaries;
- external entry points;
- authentication;
- authorization;
- least privilege;
- stronger controls for sensitive actions;
- segmentation;
- east-west traffic;
- administration;
- secrets;
- encryption;
- logging;
- monitoring;
- configuration drift;
- failure behavior;
- emergency access;
- security testing;
- recovery;
- incident response.

This checklist is intended as an architecture-review aid rather than a substitute for detailed organizational security requirements.

---

# 50. Implementation Considerations

The Python implementations are intentionally simplified models.

A production security architecture requires considerably more engineering around:

- concurrency;
- distributed systems;
- high availability;
- secure key storage;
- cryptographic implementation;
- identity federation;
- policy distribution;
- policy versioning;
- revocation;
- audit integrity;
- privacy;
- observability;
- operational recovery;
- infrastructure automation.

The purpose of the implementations is to make architectural principles executable and testable.

They should not be interpreted as production-ready replacements for mature security infrastructure.

---

# 51. Security Properties Demonstrated by the Script

The most important properties encoded in the implementation are:

### Default Deny

Unknown permissions and unknown network paths are rejected.

### Explicit Authorization

Access depends on explicit permissions.

### Contextual Authorization

Device posture, MFA, resource sensitivity, and risk influence decisions.

### Segmentation

Different zones have different communication policies.

### Defense in Depth

Multiple independent controls protect sensitive resources.

### Fail-Safe Authorization

Dependency failure does not create unintended authorization.

### Auditable Decisions

Authorization decisions produce audit events.

### Configuration Validation

Security baselines can be compared against observed configuration.

### Security Testing

Important security assumptions are represented as automated tests.

### Architectural Visualization

The architecture is represented as a diagrams.net-compatible document.

---

# 52. Real-World Relevance

Security architecture applies to:

- enterprise networks;
- banking systems;
- healthcare systems;
- government platforms;
- SaaS applications;
- cloud infrastructure;
- APIs;
- microservices;
- mobile backends;
- data platforms;
- industrial environments;
- identity platforms;
- DevOps infrastructure.

The specific technologies differ, but the architectural questions remain similar:

- What needs protection?
- Who can access it?
- Why are they allowed?
- What can they reach after compromise?
- What happens when a security control fails?
- How is suspicious behavior detected?
- How is the architecture verified after changes?

A strong architecture answers these questions explicitly rather than relying on assumptions about network location, organizational role, or trusted infrastructure.
