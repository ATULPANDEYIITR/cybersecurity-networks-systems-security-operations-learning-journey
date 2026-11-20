# Security Operations Fundamentals

## Project Overview

This project implements a Security Operations Center (SOC) workflow using Python, JavaScript, C++17, Java 17, and PostgreSQL.

It covers the operational functions required to identify, monitor, investigate, escalate, contain, and resolve cybersecurity incidents.

The central objective is to understand how security telemetry becomes actionable intelligence and how a SOC coordinates people, detection systems, procedures, and response activities.

The implementations use a realistic enterprise environment containing:

- Network firewalls.
- Endpoint Detection and Response (EDR).
- Identity and authentication systems.
- Email security gateways.
- Cloud audit monitoring.
- SOC analysts and incident responders.
- Automated detection rules.
- Incident management and operational reporting.

## 1. Mission of a Security Operations Center

A Security Operations Center is a centralized operational function responsible for monitoring an organization's security posture and coordinating responses to security threats.

Its mission is to reduce the likelihood and impact of cybersecurity incidents through continuous monitoring, detection, investigation, response, and improvement.

### Core responsibilities

| Responsibility | Operational function |
|---|---|
| Security monitoring | Collect and examine security telemetry |
| Threat detection | Identify suspicious activities and attack indicators |
| Alert triage | Determine alert relevance and priority |
| Investigation | Establish what happened and its potential impact |
| Incident response | Coordinate actions to control security incidents |
| Threat hunting | Proactively search for threats not identified by existing alerts |
| Reporting | Measure operational performance and security trends |
| Governance | Maintain documented procedures, access controls, and accountability |

A SOC does not simply monitor dashboards. It must transform security events into decisions and coordinated actions.

### SOC operational architecture

    Security Infrastructure
             |
             v
    Security Telemetry Collection
             |
             v
    SIEM / Detection Platform
             |
             v
    Correlation and Detection Rules
             |
             v
    Alert Generation
             |
             v
    L1 Initial Triage
             |
             v
    L2 Investigation
             |
             v
    L3 Advanced Analysis
             |
             v
    Incident Response
             |
             v
    Containment and Recovery
             |
             v
    Lessons Learned and Reporting

SIEM means Security Information and Event Management. It collects, normalizes, correlates, and analyzes security events from multiple sources.

EDR means Endpoint Detection and Response. It monitors endpoint activities and supports investigation and response.

These technologies provide telemetry and security capabilities. The SOC provides the operational people, processes, decisions, and accountability.

## 2. SOC Tiers and Responsibilities

SOC tiering distributes operational responsibilities according to investigation complexity, technical expertise, and decision-making authority.

The three-tier model is a common organizational arrangement, not a mandatory universal structure.

### Tier 1: Security Monitoring and Initial Triage

Tier 1 analysts are the first operational point of contact for security alerts.

Responsibilities:

- Monitor security dashboards.
- Review incoming alerts.
- Validate alert completeness.
- Identify obvious false positives.
- Check affected assets and users.
- Correlate basic authentication and network information.
- Classify and prioritize alerts.
- Record initial evidence.
- Escalate suspicious or complex incidents.

Typical activities include examining repeated failed authentication attempts, reviewing endpoint malware notifications, and checking reported phishing emails.

Tier 1 should not dismiss an alert merely because the available information is incomplete.

### Tier 2: Incident Investigation and Response

Tier 2 analysts conduct deeper technical investigations.

Responsibilities:

- Examine endpoint and network telemetry.
- Correlate events across multiple systems.
- Investigate suspicious authentication.
- Analyze malware behavior.
- Examine lateral movement indicators.
- Determine affected accounts and systems.
- Recommend or coordinate containment.
- Escalate advanced threats.

Tier 2 converts an initial security alert into a technically supported incident assessment.

### Tier 3: Advanced Threat Analysis

Tier 3 analysts handle complex and advanced investigations.

Responsibilities:

- Threat hunting.
- Advanced malware analysis.
- Digital forensic investigations.
- Attack-chain reconstruction.
- Advanced intrusion analysis.
- Detection engineering.
- Threat intelligence correlation.
- Identification of previously unknown attack techniques.

Tier 3 may also support security architecture and improvements to detection capabilities.

### Tier comparison

| Attribute | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| Primary function | Monitoring | Investigation | Advanced analysis |
| Typical input | Alerts | Escalated alerts | Complex incidents |
| Technical depth | Basic to intermediate | Advanced | Specialist |
| Initial triage | Primary | Secondary | As required |
| Malware investigation | Initial review | Detailed analysis | Advanced analysis |
| Threat hunting | Limited | Supporting | Primary |
| Incident escalation | To L2 | To L3 | Specialist coordination |
| Detection engineering | Limited | Supporting | Advanced |

Escalation should depend on technical complexity, potential business impact, urgency, and available expertise rather than severity alone.

## 3. Security Monitoring

Security monitoring is the continuous observation and analysis of security-related activities across an organization's infrastructure.

Its purpose is to identify abnormal behavior, suspicious activities, security control failures, and potential attacks.

### Monitoring sources

| Source | Information collected | Example security indicator |
|---|---|---|
| Firewall | Network connections and traffic | Repeated connection attempts |
| EDR | Endpoint processes and behavior | Malware execution |
| Identity provider | Authentication and authorization | Repeated login failures |
| Email gateway | Email delivery and inspection | Phishing attachment |
| DNS monitoring | Domain requests | Communication with suspicious domains |
| Cloud audit logs | Administrative activities | Unauthorized configuration changes |
| Network IDS | Network traffic signatures | Exploit signature detection |

### Security event

A security event is an observable occurrence in an information system.

Examples:

- A successful login.
- A failed login.
- A firewall connection.
- A process execution.
- A file modification.
- A cloud configuration change.

Not every security event represents a threat.

### Security alert

An alert is a notification generated when a detection rule, correlation mechanism, or analytical process identifies activity requiring attention.

For example:

Twenty-five failed authentication attempts from a single source may trigger a brute-force detection alert.

An alert is an investigation lead, not automatic proof of a successful attack.

### Event, alert, and incident distinctions

| Term | Meaning |
|---|---|
| Event | An observable system occurrence |
| Alert | A notification generated by a detection mechanism |
| Incident | A confirmed or formally managed security event requiring response |
| Evidence | Information supporting an investigation or decision |
| Indicator of Compromise | An observable artifact associated with potential malicious activity |

The implementations preserve these distinctions through separate event, alert, evidence, and incident models.

### Monitoring approaches

**Signature-based monitoring**

Matches activity against known attack signatures or patterns.

Example: Detecting network traffic matching a known malicious signature.

**Threshold-based monitoring**

Generates alerts when a measurable value exceeds a defined threshold.

Example: Ten or more failed authentication attempts.

**Behavior-based monitoring**

Identifies deviations from expected behavior.

Example: A user account accessing unusual systems at an unusual time.

**Correlation-based monitoring**

Connects multiple events to identify a larger suspicious activity pattern.

Example:

- Repeated login failures.
- A successful login.
- Privileged account access.
- Unusual outbound data transfer.

Individually, these events may not establish an attack. Together, they may justify an investigation.

## 4. Alerting and Detection Engineering

Alerting converts monitoring observations into actionable notifications.

An effective alert should provide sufficient context for an analyst to determine its relevance and urgency.

### Alert components

| Field | Purpose |
|---|---|
| Alert ID | Unique identification |
| Event source | Originating security system |
| Event timestamp | Time of observed activity |
| Source IP | Origin of network activity |
| Destination | Affected system or endpoint |
| Detection rule | Mechanism that generated the alert |
| Severity | Operational priority |
| Confidence | Strength of the detection assessment |
| Evidence | Supporting technical information |
| Assigned analyst | Responsible individual |
| Status | Current investigation state |

### Detection thresholds

The implementations demonstrate three principal detection patterns.

| Detection condition | Classification | Severity |
|---|---|---|
| 10 failed authentication attempts | Brute force | High |
| 25 failed authentication attempts | Brute force | Critical |
| Malware detection | Malware | High |
| User-reported phishing | Phishing | Medium |
| Outbound transfer of at least 500 MB | Potential exfiltration | Critical |
| Normal traffic | No alert | Not applicable |

These values are illustrative demonstration thresholds, not universal security standards.

Production thresholds must account for historical baselines, asset criticality, identity context, detection quality, and business activity.

### Alert confidence

Confidence represents the strength of supporting evidence for a detection.

A high confidence score does not automatically mean that an alert is a confirmed incident.

Severity and confidence measure different things:

- Severity represents potential operational impact or urgency.
- Confidence represents the strength of the detection assessment.

A high-severity alert with limited evidence can still require urgent investigation.

### False positives and false negatives

A false positive occurs when legitimate activity is incorrectly classified as suspicious.

A false negative occurs when malicious activity is not detected.

Both affect SOC effectiveness.

| Problem | Operational consequence |
|---|---|
| Excessive false positives | Alert fatigue and wasted investigation time |
| False negatives | Undetected security incidents |
| Missing telemetry | Incomplete investigation |
| Poor thresholds | Inaccurate alert volume |
| Duplicate alerts | Repeated work and distorted reporting |
| Incorrect timestamps | Misleading event correlation |

Detection engineering should balance detection coverage, precision, operational cost, and response urgency.

## 5. Alert Triage and Prioritization

Alert triage is the initial assessment process used to determine whether an alert requires further investigation.

The analyst evaluates the alert's technical evidence, affected assets, identity context, potential impact, and detection reliability.

### Triage workflow

    Incoming Alert
          |
          v
    Validate Alert Data
          |
          v
    Identify Affected Asset
          |
          v
    Examine Source and Destination
          |
          v
    Correlate Related Events
          |
          v
    Evaluate Severity and Confidence
          |
          v
    Classify Alert
          |
          +----------------------+
          |                      |
          v                      v
     False Positive         Suspicious
          |                      |
          v                      v
       Document              Investigate
          |                      |
          v                      v
       Close                 Escalate

### Priority considerations

An analyst should consider:

- Business criticality of the affected asset.
- Whether privileged accounts are involved.
- Evidence of unauthorized access.
- Number of affected systems.
- Potential data exposure.
- Attack persistence.
- Whether the activity is ongoing.
- Confidence in the detection.
- Availability of containment options.

A critical alert should receive immediate attention even when the full investigation is incomplete.

## 6. Alert Escalation

Escalation transfers responsibility or requests specialist support when an alert exceeds the current analyst's authority, expertise, or response capability.

### Escalation conditions

- Technical complexity exceeds Tier 1 capability.
- Malware requires advanced analysis.
- Evidence indicates possible data exfiltration.
- Privileged accounts are compromised.
- Multiple systems are affected.
- A critical business service is threatened.
- An analyst cannot complete the investigation within the response target.
- A containment action requires additional authorization.

### Escalation model

| Source tier | Destination tier | Typical reason |
|---|---|---|
| Tier 1 | Tier 2 | Complex investigation |
| Tier 2 | Tier 3 | Advanced threat analysis |
| Tier 1 | Tier 3 | Critical incident requiring specialist intervention |
| Tier 3 | Incident management | Coordinated organizational response |

### Escalation information

An escalation record should include:

- Incident identifier.
- Original assigned analyst.
- Destination tier.
- Escalation reason.
- Investigation findings.
- Supporting evidence.
- Actions already performed.
- Pending decisions.
- Timestamp.
- Acknowledgement by the receiving team.

Escalation must preserve investigation continuity. Transferring an alert without its evidence and investigative history creates unnecessary delays.

### Assignment considerations

The implementations use severity-based minimum tier requirements and analyst skills.

An analyst must:

- Be active.
- Possess the relevant incident skill.
- Meet the minimum required tier.
- Have available assignment capacity.

If no eligible analyst exists, the alert is escalated instead of silently remaining unassigned.

## 7. Incident Management Lifecycle

Incident management coordinates the organizational response to a security incident.

The lifecycle provides a controlled progression from initial detection through investigation, containment, resolution, and closure.

A practical lifecycle is:

### Detection

A monitoring system identifies suspicious activity.

Example: EDR reports malware execution on a workstation.

### Reporting and identification

The alert is reviewed, classified, and associated with a potential incident.

Analysts establish:

- What happened.
- When it happened.
- Which systems are affected.
- Which users may be involved.
- Whether the activity is ongoing.

### Investigation

The SOC examines relevant evidence and reconstructs the activity.

Typical investigation sources include:

- Authentication records.
- Endpoint process logs.
- Network connections.
- DNS queries.
- Firewall records.
- Cloud audit events.
- Email security records.

### Containment

Containment limits the incident's ability to spread or cause further damage.

Examples:

- Isolating a compromised endpoint.
- Blocking a malicious network source.
- Disabling a compromised account.
- Revoking compromised credentials.
- Restricting suspicious network traffic.

Containment actions must follow organizational authorization procedures and consider operational impact.

### Eradication

Eradication removes the underlying cause and malicious artifacts.

Examples include:

- Removing malicious files.
- Eliminating persistence mechanisms.
- Patching exploited vulnerabilities.
- Removing unauthorized accounts.
- Correcting insecure configurations.

### Recovery

Recovery restores affected systems and business operations.

Systems should be validated before being returned to normal operation.

Monitoring should continue to detect possible reinfection or attacker persistence.

### Closure

Closure confirms that required response activities have been completed and documented.

A closure record should include:

- Root cause.
- Impact assessment.
- Investigation findings.
- Containment activities.
- Eradication activities.
- Recovery validation.
- Evidence references.
- Lessons learned.
- Approval or authorization where required.

### Lifecycle state model

The implementations use explicit state transitions:

    NEW
     |
     v
    TRIAGED
     |
     v
    INVESTIGATING
     |
     +-----------> ESCALATED
     |                  |
     |                  v
     |             INVESTIGATING
     |                  |
     +------------------+
     |
     v
    CONTAINED
     |
     v
    RESOLVED
     |
     v
    CLOSED

A false-positive determination can be made during the permitted investigation stages and subsequently closed.

Invalid transitions are rejected.

For example, an incident cannot move directly from NEW to CLOSED.

The state machine prevents premature closure and preserves a meaningful operational history.

## 8. SOC Operational Metrics

SOC metrics measure detection performance, operational workload, response effectiveness, and monitoring reliability.

### Mean Time to Detect

MTTD measures the time between the beginning of an identifiable malicious activity and its detection.

A simplified calculation is:

MTTD = Detection Time - Attack Start Time

Accurate measurement requires an independently established attack start time.

### Mean Time to Acknowledge

MTTA measures the time between alert generation and analyst acknowledgement.

MTTA = Acknowledgement Time - Alert Time

### Mean Time to Respond

MTTR is used in different ways across organizations. Its exact definition should be documented.

A SOC may use it to measure the time between incident detection and the start of an effective response.

### Mean Time to Resolve

MTTR, when used as Mean Time to Resolve:

MTTR = Resolution Time - Detection Time

### False Positive Rate

False Positive Rate = False Positive Alerts / Total Alerts

This project calculates a simplified operational false-positive proportion using classified alert records.

It is not equivalent to the statistical false-positive rate used in a classification confusion matrix, which requires actual negative observations.

### Additional operational indicators

| Metric | Operational purpose |
|---|---|
| Total alerts | Monitoring workload |
| Critical alerts | High-priority workload |
| Active incidents | Unresolved operational exposure |
| Escalation rate | Specialist dependency |
| Analyst workload | Assignment distribution |
| Detection coverage | Visibility across assets |
| Source availability | Monitoring infrastructure reliability |
| Ingestion delay | Telemetry freshness |
| False-positive proportion | Detection quality |
| Resolution time | Incident response effectiveness |

Metrics should be interpreted together. A low alert volume does not necessarily indicate a secure environment because it may also reflect incomplete monitoring.

## 9. Implementation: Python

The Python implementation models SOC operations using an object-oriented workflow.

### Main components

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Validated telemetry record |
| `DetectionEngine` | Rule-based event classification |
| `Alert` | Detection result and evidence |
| `AnalystRegistry` | Analyst registration and skill lookup |
| `EscalationEngine` | Tier selection and assignment |
| `IncidentManager` | Incident state transitions |
| `SOCReporter` | Operational reporting |

### Important implementation decisions

Dataclasses provide structured security event and alert representations.

Enums prevent inconsistent values for severity, status, incident type, and SOC tier.

The detection engine uses explicit thresholds and rule-based classification.

The analyst registry uses dictionaries for efficient identity lookup.

The escalation engine selects qualified analysts and handles unavailability.

The incident manager uses an explicit transition map to prevent invalid lifecycle changes.

The reporting component uses `Counter` to aggregate alert distributions.

JSON export provides a persistent operational report.

The test suite validates:

- Critical alert detection.
- Invalid IP rejection.
- Successful incident lifecycle progression.
- Rejection of invalid transitions.

### Execution

Run the script with Python 3.10 or later.

It uses only the Python standard library.

## 10. Implementation: JavaScript

The JavaScript implementation provides an event-driven SOC monitoring architecture.

### Main components

| Component | Responsibility |
|---|---|
| `DetectionEngine` | Event classification |
| `AnalystDirectory` | Analyst registration and workload management |
| `IncidentService` | Assignment and state transitions |
| `SOCMonitoringSystem` | Event queue and event processing |
| `calculateMetrics` | Operational aggregation |
| `saveReport` | JSON report persistence |

### Event-driven processing

The monitoring system extends Node.js `EventEmitter`.

New security events enter a bounded processing queue.

The monitoring service processes each event, generates alerts, assigns analysts, and emits alert notifications.

This separates event ingestion from downstream alert handling.

### Concurrency and state management

The analyst directory uses `Map` for identity management and `Set` for analyst skills.

Assignment counters track analyst workload.

Queue capacity is bounded to prevent unlimited memory consumption.

The asynchronous queue processor yields periodically to the Node.js event loop.

The implementation also rejects duplicate events and invalid state transitions.

### Execution

Run with Node.js 18 or later.

The application requires no external npm dependencies.

## 11. Implementation: C++17

The C++ implementation emphasizes domain modeling, deterministic state management, and efficient operational processing.

### Main components

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Event validation |
| `Analyst` | Analyst identity and assignment capacity |
| `Alert` | Security detection record |
| `DetectionEngine` | Classification rules |
| `AnalystRegistry` | Skill-based analyst assignment |
| `IncidentManager` | Lifecycle enforcement |
| `SOCPlatform` | Integrated monitoring workflow |
| `SOCMetrics` | Operational reporting |

### Important design decisions

Enums represent controlled operational states.

Structs model events, analysts, alerts, and audit entries.

`unordered_map` provides average constant-time identity lookup.

`set` prevents duplicate analyst skills and processed event identifiers.

`optional` represents detection results and analyst availability without using invalid sentinel values.

STL algorithms select suitable analysts according to tier, expertise, and workload.

Exceptions provide explicit failure handling.

### Complexity considerations

Let:

- E represent the number of processed events.
- A represent the number of registered analysts.
- S represent the average number of skills per analyst.

Detection is approximately O(1) per event for the implemented fixed rule set.

Analyst selection examines available analysts and sorts eligible candidates, giving an approximate O(A log A) worst-case selection cost.

Processed event identity lookup uses an unordered set with average O(1) lookup.

Reporting requires O(E) traversal over generated alerts.

The implementation uses a bounded event count to limit memory consumption.

### Execution

Compile with a C++17-compatible compiler.

The program uses no third-party libraries.

## 12. Implementation: Java 17

The Java implementation presents an enterprise-oriented domain and service architecture.

### Main components

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Immutable validated event |
| `Analyst` | Immutable analyst definition |
| `Alert` | Incident detection and audit state |
| `DetectionService` | Detection abstraction |
| `RuleBasedDetectionService` | Detection implementation |
| `AnalystAssignmentService` | Concurrent assignment management |
| `IncidentPolicy` | Permitted lifecycle transitions |
| `IncidentManagementService` | Incident operations |
| `SOCMonitoringService` | Event ingestion and orchestration |
| `SOCReportingService` | Operational metrics |

### Enterprise design decisions

Java records represent immutable event and analyst data.

Interfaces separate detection contracts from implementation details.

Custom exceptions distinguish validation, assignment, and transition failures.

`ConcurrentHashMap` provides concurrent identity storage.

`AtomicInteger` supports atomic analyst workload updates.

The incident policy separates state-transition rules from incident processing.

The monitoring service separates event ingestion from incident management.

The reporting service uses Streams and collectors for aggregation.

The implementation demonstrates how domain objects, policy objects, and service classes can form a maintainable enterprise security operations application.

### Execution

Compile and execute with Java 17.

The program has no third-party dependencies.

## 13. Implementation: PostgreSQL

The PostgreSQL implementation models the SOC as a relational operational system.

It preserves relationships between security telemetry, detection rules, analysts, alerts, incidents, evidence, escalation records, and response actions.

### Database architecture

    SOC SCHEMA
        |
        +-- SOC_ROLES
        |
        +-- ANALYSTS
        |      |
        |      +-- ANALYST_SKILLS
        |
        +-- MONITORING_SOURCES
        |      |
        |      +-- SECURITY_EVENTS
        |              |
        |              +-- ALERTS
        |                    |
        |                    +-- ALERT_EVIDENCE
        |                    |
        |                    +-- INCIDENTS
        |                           |
        |                           +-- INCIDENT_HISTORY
        |                           |
        |                           +-- ESCALATIONS
        |                           |
        |                           +-- RESPONSE_ACTIONS
        |
        +-- DETECTION_RULES
        |
        +-- ESCALATION_POLICIES
        |
        +-- MONITORING_HEALTH

### Relational model

| Table | Purpose |
|---|---|
| `soc_roles` | Operational role definitions |
| `analysts` | SOC workforce |
| `analyst_skills` | Technical capabilities |
| `monitoring_sources` | Telemetry source inventory |
| `security_events` | Collected security events |
| `detection_rules` | Detection configuration |
| `alerts` | Generated security alerts |
| `alert_evidence` | Supporting investigation evidence |
| `incidents` | Managed security incidents |
| `incident_history` | State-transition audit records |
| `escalations` | Tier escalation history |
| `response_actions` | Recorded response activities |
| `escalation_policies` | Severity-based operational policies |
| `monitoring_health` | Telemetry infrastructure health |

### Database integrity

Primary keys identify individual records.

Foreign keys maintain relationships between events, alerts, analysts, and incidents.

Unique constraints prevent duplicate external event identifiers.

Check constraints validate numeric values, confidence scores, and required lifecycle timestamps.

Indexes support common operational retrieval patterns.

The JSONB metadata field supports structured event attributes without requiring a separate column for every vendor-specific field.

### Database functions

`analyst_workload()` calculates an analyst's current active workload.

`find_eligible_analyst()` evaluates incident skill, minimum tier, active status, proficiency, and assignment capacity.

### Database procedures

`ingest_security_event()` validates incoming telemetry, records an event, evaluates detection rules, and creates an alert and incident when appropriate.

`assign_incident()` selects an eligible analyst and updates the incident and alert.

`transition_incident()` performs a validated incident state transition.

`escalate_incident()` records an escalation and updates the incident's operational status.

### Database triggers

`trg_validate_incident_transition` prevents unauthorized lifecycle transitions.

`trg_audit_incident_status` creates an audit record whenever an incident status changes.

`trg_alert_timestamp` maintains alert modification timestamps.

The audit mechanism records actor and reason using transaction-local PostgreSQL settings.

### Database views

`v_soc_alert_dashboard` combines alert, event, analyst, and incident information.

`v_analyst_workload` presents current and historical analyst assignments.

`v_monitoring_health` exposes the latest monitoring-source health record.

### SQL operational queries

The script includes queries for:

- Alert retrieval.
- Severity aggregation.
- Incident lifecycle duration.
- Escalation analysis.
- Analyst workload.
- Detection effectiveness.
- Executive reporting.
- Eligible analyst selection.
- Overdue incident acknowledgement.
- Monitoring source health.
- Event correlation by IP address.
- Unresolved incidents.
- Incident audit history.
- Relational integrity validation.

### Transaction handling

The complete SQL setup runs inside a transaction.

Incident state changes use row locking to reduce conflicting updates.

A failed transition is handled without leaving a partially completed transition.

The SQL example also demonstrates safe rejection of duplicate external event identifiers.

## 14. Security and Operational Controls

A production SOC requires additional controls beyond detection and incident workflow logic.

### Access control

Analyst access should follow role-based access control.

| Role | Typical permissions |
|---|---|
| L1 analyst | View alerts, triage, document findings |
| L2 responder | Investigate and coordinate authorized response |
| L3 specialist | Advanced forensic and threat-hunting access |
| SOC manager | Operational oversight and reporting |
| Security administrator | Controlled platform configuration |

Privileged operations should require authorization, separation of duties, and auditable approval.

### Evidence integrity

Incident evidence should preserve:

- Original collection timestamps.
- Collection source.
- Collector identity.
- Evidence references.
- Cryptographic integrity hashes.
- Access history.
- Retention information.

Evidence should not be silently modified during investigation.

The SQL schema provides evidence references and an integrity-hash field. It does not implement full forensic chain-of-custody enforcement.

### Logging and auditability

Security operational records should capture:

- Event ingestion.
- Detection decisions.
- Analyst assignments.
- Investigation activities.
- Escalation decisions.
- Containment actions.
- Resolution activities.
- Incident closure.

Audit records should be protected against unauthorized modification.

### Data protection

Security telemetry may contain personal information, authentication metadata, network addresses, and confidential business information.

Production deployments should implement:

- Encryption in transit.
- Encryption at rest.
- Restricted database permissions.
- Secret management.
- Data retention policies.
- Sensitive-data minimization.
- Controlled export permissions.
- Secure backup and recovery.

### Automated response safeguards

Automated containment can interrupt legitimate business operations.

High-impact actions should have appropriate authorization, asset criticality checks, exception handling, and rollback procedures.

Detection confidence alone should not authorize destructive or disruptive response actions.

## 15. Failure Scenarios and Edge Cases

| Failure scenario | Expected operational handling |
|---|---|
| Invalid event timestamp | Reject event |
| Invalid IP address | Reject event |
| Duplicate event | Prevent duplicate processing |
| Missing monitoring source | Record ingestion failure |
| Detection rule disabled | Do not generate an alert from that rule |
| No eligible analyst | Escalate or raise an assignment exception |
| Analyst capacity exceeded | Select another eligible analyst |
| Missing evidence | Prevent containment transition |
| Invalid lifecycle transition | Reject transition |
| Duplicate alert | Preserve unique identity |
| Monitoring source unavailable | Report telemetry health failure |
| Delayed event ingestion | Preserve event time and ingestion time |
| Database transaction failure | Roll back incomplete operations |
| Report persistence failure | Report the export error |

A production deployment should also account for:

- Event bursts.
- Queue backpressure.
- Time synchronization problems.
- Missing telemetry.
- Detection rule versioning.
- Alert deduplication.
- Distributed processing.
- Database failover.
- Analyst shift handover.
- Incident ownership changes.
- Evidence retention requirements.

## 16. Implementation Scope and Limitations

These five implementations are operational learning models rather than complete commercial SOC platforms.

The detection rules are deterministic demonstrations and do not provide comprehensive attack detection.

The severity thresholds are illustrative.

The event queues and analyst assignment models are designed for demonstration workloads rather than distributed production deployment.

The code does not directly connect to SIEM, EDR, firewall, cloud, or identity-provider APIs.

The PostgreSQL schema provides relational integrity and lifecycle enforcement but does not implement complete enterprise RBAC, immutable evidence storage, or distributed event ingestion.

The JavaScript and Java examples demonstrate in-process concurrency controls, not a complete distributed locking or messaging architecture.

The C++ implementation demonstrates an integrated governance and processing model rather than a production-grade high-throughput streaming engine.

The Python and JavaScript examples persist reports locally. Their filesystem protections do not replace operating-system access controls or secure centralized audit storage.

These boundaries are important when distinguishing an educational SOC workflow from an operational security service.

## 17. Cross-Language Technical Comparison

| Capability | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Event modeling | Dataclasses | Objects | Structs | Records | Tables |
| Detection | Rule engine | Rule engine | Rule engine | Detection service | Stored procedure |
| Analyst management | Dictionary | Map | Unordered map | Concurrent map | Relational tables |
| Skill management | Sets | Sets | STL sets | Immutable sets | Skill table |
| Incident lifecycle | State machine | State machine | State machine | Policy object | Trigger |
| Escalation | Service | Service | Manager | Service | Procedure |
| Audit history | Lists | Arrays | Vectors | Immutable records | Audit table |
| Reporting | Counter | Map aggregation | Struct aggregation | Streams | Views and CTEs |
| Validation | Exceptions | Exceptions | Exceptions | Custom exceptions | Constraints and triggers |
| Persistence | JSON | JSON | In-memory | In-memory | Relational database |

## 18. Learning Outcomes

The implementations establish the following technical distinctions:

- SOC monitoring observes security activity.
- Detection identifies potentially suspicious behavior.
- Alerting communicates a detection result.
- Triage evaluates whether the alert requires further action.
- Escalation transfers responsibility or requests specialist intervention.
- Investigation establishes the technical circumstances and impact.
- Containment limits ongoing damage.
- Eradication removes the underlying threat.
- Recovery restores normal operations.
- Closure documents the completed response.

The most important operational relationship is:

**Security telemetry → Detection → Alert → Triage → Investigation → Escalation → Containment → Eradication → Recovery → Closure → Continuous Improvement**

A SOC becomes effective when its detection capabilities, analyst responsibilities, response procedures, operational measurements, and governance controls function as one coordinated system.
