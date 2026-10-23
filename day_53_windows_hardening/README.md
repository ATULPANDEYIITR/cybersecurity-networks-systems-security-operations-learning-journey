# Windows Hardening: Defender, Firewall, Security Policies, Application Controls, and Attack Surface Reduction

## Scope

This project models a Windows endpoint-hardening program as a set of explicit security controls rather than as a collection of unrelated configuration switches.

The five implementations use the same security domain but different engineering perspectives:

| File | Technical perspective | Main responsibility |
|---|---|---|
| Python | Endpoint policy simulator | Validate endpoint state and compare it with a hardening baseline |
| JavaScript | Event-driven policy evaluator | Process policy groups asynchronously and emit security findings |
| C++17 | Native governance engine | Apply strongly typed compliance rules with explicit severity and remediation |
| Java 17 | Enterprise domain model | Separate policies, endpoint state, assessment rules, and service orchestration |
| PostgreSQL | Relational compliance system | Persist endpoint state, baselines, ASR rules, assessments, and findings |

The implementations are assessment-oriented. They do not silently modify Windows security settings. This is deliberate: hardening changes can affect connectivity, application compatibility, authentication, and operational workflows, so configuration changes should be reviewed and deployed through controlled administrative processes.

## Security Model

Windows hardening is represented as five related control domains:

    Windows Endpoint
          |
          +-- Microsoft Defender
          |      |
          |      +-- Real-time protection
          |      +-- Behavior monitoring
          |      +-- Cloud protection
          |      +-- IOAV protection
          |      +-- Tamper protection
          |
          +-- Windows Firewall
          |      |
          |      +-- Domain profile
          |      +-- Private profile
          |      +-- Public profile
          |      +-- Default inbound policy
          |
          +-- Security Policies
          |      |
          |      +-- Password and lockout controls
          |      +-- Logon auditing
          |      +-- Process creation auditing
          |      +-- PowerShell logging
          |
          +-- Application Control
          |      |
          |      +-- Audit or enforcement mode
          |      +-- Publisher rules
          |      +-- Path rules
          |      +-- Unsigned executable restrictions
          |
          +-- Attack Surface Reduction
                 |
                 +-- Rule-specific Audit/Block states
                 +-- Office execution restrictions
                 +-- Process-injection protections
                 +-- Email/web-delivered executable restrictions

These domains have different purposes. Defender focuses on malicious content and behavior. Firewall controls network traffic. Security policies govern authentication and auditing. Application control determines which executable content is permitted. ASR rules reduce risky application behaviors before they become successful attack paths.

## Microsoft Defender

The Defender model distinguishes protection state from signature freshness.

The Python implementation uses `DefenderConfig` as an immutable policy/state object. The evaluator compares real-time monitoring, behavior monitoring, IOAV protection, cloud protection, and tamper protection independently. A disabled real-time or tamper-protection control receives critical severity because the resulting exposure affects the endpoint's core defensive posture.

Signature age is represented separately as an integer number of hours. A system can have every protection flag enabled while still using stale security intelligence. The baseline therefore treats excessive signature age as an independent finding.

The C++ implementation applies the same principle using strongly typed structures and fixed-size collections. This prevents accidental omission of one of the defined Defender controls during evaluation.

The Java implementation uses records for Defender policy and observed state. Records make the domain objects concise and immutable, which is useful when an assessment must operate against a consistent snapshot.

The PostgreSQL model stores Defender state in `defender_state` and the required Defender posture in `baseline_defender`. This separates observed telemetry from organizational policy.

### Important operational distinction

A hardening baseline defines what should be true. Endpoint telemetry defines what is true now.

    Baseline policy  ───────┐
                            ├──> Compliance evaluation ──> Finding
    Endpoint telemetry ─────┘

This separation permits the same endpoint state to be evaluated against different organizational baselines.

## Windows Firewall

Windows Firewall is modeled by profile because Domain, Private, and Public network contexts have different trust assumptions.

The baseline requires all three profiles to be enabled and requires inbound traffic to be blocked by default. Explicit firewall rules can then provide required exceptions.

The implementations intentionally do not assume that all outbound traffic must be blocked. The sample baseline uses:

| Profile | Enabled | Default inbound | Default outbound |
|---|---|---|---|
| Domain | Yes | Block | Allow |
| Private | Yes | Block | Allow |
| Public | Yes | Block | Allow |

The Public profile receives critical severity when disabled because an endpoint operating on an untrusted network without the expected firewall boundary has a particularly significant exposure.

The SQL design uses a composite key on `(endpoint_id, profile)`. This guarantees that an endpoint cannot have two independent Domain-profile records at the same time.

The SQL assessment also identifies missing firewall telemetry. Missing telemetry is not treated as equivalent to a secure configuration. An administrator needs to distinguish:

- The control is correctly configured.
- The control is incorrectly configured.
- The control could not be measured.

That distinction is important in compliance systems.

## Security Policies and Auditing

Security policy controls cover authentication resilience and security visibility.

The examples include:

- Minimum password length.
- Account lockout threshold.
- Lockout duration.
- Logon auditing.
- Process creation auditing.
- PowerShell script block logging.
- PowerShell transcription.

Authentication controls reduce the impact of password guessing and weak credentials. Auditing controls provide evidence that can be used during incident investigation.

The sample baseline requires a 14-character password minimum and a five-attempt lockout threshold. These are policy examples rather than universal values. An organization may choose different values according to its identity architecture, regulatory obligations, authentication technology, and operational requirements.

PowerShell logging is evaluated independently from Defender. Endpoint protection and security telemetry answer different questions:

| Control | Primary question |
|---|---|
| Defender | Is malicious or suspicious activity being detected and prevented? |
| Process auditing | Which processes were created? |
| Script block logging | What PowerShell content was processed? |
| Transcription | What PowerShell session activity was recorded? |

The Python, C++, Java, and SQL implementations therefore keep auditing as a separate security-policy domain.

## Application Control

Application control is represented with four properties:

- Enforcement mode.
- Publisher rules.
- Path rules.
- Unsigned-binary blocking.

The key distinction is between auditing and enforcement.

In `AUDIT` mode, policy violations can be observed without necessarily preventing execution. This can be useful when building a new policy because existing applications and administrative tools may depend on executable content that the proposed policy would block.

In `BLOCK` mode, the policy is intended to enforce the allowed execution model.

The sample endpoint intentionally operates in `AUDIT` mode while the enterprise baseline requires `BLOCK`. The assessment therefore reports a policy gap instead of assuming that an audited rule is equivalent to an enforced rule.

Application control also has a compatibility trade-off. Aggressive rules can interfere with:

- Internally developed applications.
- Installers and update mechanisms.
- Administrative scripts.
- Legacy software.
- Software installed outside expected paths.

For this reason, application-control changes should normally progress through validation, audit observation, exception review, and controlled enforcement.

## Attack Surface Reduction

ASR is modeled as individual rules rather than one global switch.

Each rule contains:

- A stable rule identifier.
- A human-readable description.
- Required enforcement state.
- Severity.

The implementations include representative controls covering executable content originating from email/webmail, Office-generated executable content, process injection, and Office communication applications creating child processes.

The important design property is that one ASR rule can be in `BLOCK` while another is in `AUDIT`.

    Rule A -> BLOCK
    Rule B -> BLOCK
    Rule C -> BLOCK
    Rule D -> AUDIT

This is different from treating ASR as a single enabled/disabled feature.

The SQL schema uses `UUID` for ASR rule identifiers and a composite primary key on endpoint/rule pairs. A missing endpoint ASR state is interpreted as `DISABLED` during compliance evaluation. That prevents absent telemetry from being silently interpreted as compliance.

## Python Implementation

The Python program is a policy simulator built around dataclasses.

`WindowsEndpoint` represents observed endpoint state. `Baseline` represents required state. `HardeningEvaluator` performs the comparison and produces immutable `Finding` records.

The implementation demonstrates:

- Structured endpoint modeling.
- Validation before evaluation.
- Dictionary-based ASR lookup.
- Firewall-profile lookup.
- Independent control-family evaluation.
- Severity assignment.
- Diagnostic command generation.
- Unit tests for compliance and invalid data.
- Exception-based validation.

The PowerShell output is deliberately diagnostic rather than automatically executable configuration logic. Commands such as `Get-MpComputerStatus`, `Get-NetFirewallProfile`, `auditpol`, and `Get-AppLockerPolicy` allow an administrator to inspect the affected security subsystem before making a change.

The self-tests include a compliant endpoint, invalid hostname handling, and missing ASR-rule detection.

Run with Python 3:

`python windows_hardening.py`

The program returns findings for the intentionally non-compliant demonstration endpoint and confirms that no Windows configuration is changed.

## JavaScript Implementation

The JavaScript implementation takes an event-driven approach.

`WindowsHardeningPolicy` validates the baseline. `EndpointAssessment` evaluates individual control families. `EventBus` publishes findings as they are produced.

The assessment method is asynchronous even though the sample uses local objects. This models a common endpoint-management architecture where Defender telemetry, firewall state, security-policy data, and application-control state can arrive from different sources.

The implementation uses:

- Classes for policy and assessment behavior.
- Immutable configuration objects with `Object.freeze`.
- `structuredClone` to isolate assessment input.
- Asynchronous policy stages.
- An event bus for findings.
- `Map` for firewall profile lookup.
- `Set` for unique diagnostic commands.
- Explicit validation errors.

Run with Node.js:

`node windows_hardening.js`

The application prints findings and reviewable diagnostic PowerShell commands. It does not invoke those commands.

## C++17 Implementation

The C++ implementation is a native governance engine rather than a direct translation of the Python program.

The design uses:

- `enum class` for enforcement and severity.
- Fixed-size `std::array` for the three firewall profiles.
- `std::unordered_map` for ASR state.
- Immutable baseline state held by the evaluator.
- Explicit validation functions.
- Structured findings.
- Exception handling.
- Regular-expression validation for hostnames.

`HardeningEngine` owns the policy baseline and exposes `evaluate()` as a read-only assessment operation.

The firewall model uses an array because the security model explicitly expects Domain, Private, and Public profiles. ASR rules use an unordered map because rule identifiers are sparse UUID-like keys and direct lookup is more appropriate than positional indexing.

The program exits with a non-zero status when findings exist. This is useful for automation because a scheduled compliance job can distinguish:

    0 -> no findings
    2 -> assessment completed with findings
    1 -> assessment failed

The distinction between an assessment failure and a successful non-compliant assessment is important in security automation.

Compile with:

`g++ -std=c++17 -O2 windows_hardening.cpp -o windows_hardening`

## Java 17 Implementation

The Java implementation models enterprise governance through explicit domain types and interchangeable assessment rules.

Records represent immutable policy and endpoint-state objects:

- `DefenderPolicy`.
- `FirewallProfilePolicy`.
- `SecurityPolicy`.
- `ApplicationControlPolicy`.
- `AsrPolicy`.
- `EndpointState`.
- `Finding`.

`AssessmentRule` provides a domain-level contract. Separate implementations evaluate Defender, firewall, security-policy, application-control, and ASR controls.

`HardeningAssessmentService` composes those rules into a single assessment service.

This structure is useful when an enterprise security platform grows beyond one baseline. New policy domains can be introduced as separate assessment rules without changing the central service's control flow.

The Java implementation also distinguishes baseline policy from observed state. The service never treats the observed endpoint as authoritative merely because the endpoint reports a value.

Compile and run with Java 17:

`javac WindowsHardeningGovernance.java`

`java WindowsHardeningGovernance`

The program reports severity counts and detailed remediation information.

## PostgreSQL Model

The SQL implementation provides the persistent compliance layer.

The main relationships are:

    endpoints
       |
       +---- defender_state
       |
       +---- firewall_state
       |
       +---- security_policy_state
       |
       +---- application_control_state
       |
       +---- endpoint_asr_state ---- asr_rules
       |
       +---- hardening_assessments ---- hardening_findings

    hardening_baselines
       |
       +---- baseline_defender
       +---- baseline_firewall_profiles
       +---- baseline_security_policy
       +---- baseline_application_control

Foreign keys preserve relationships between endpoint observations, policies, rules, assessments, and findings.

Check constraints reject structurally invalid values such as negative Defender signature age, invalid password lengths, and unsupported firewall actions.

The SQL script demonstrates several PostgreSQL-specific mechanisms:

- Custom enum types.
- Identity columns.
- UUID identifiers.
- Foreign keys.
- Check constraints.
- Partial indexes.
- PL/pgSQL functions.
- Triggers.
- Common table expressions.
- Filtered aggregates.
- Transactional assessment insertion.

`evaluate_endpoint()` is the central database-side compliance function. It reads the current endpoint state and baseline and returns findings without changing the endpoint configuration.

The assessment transaction creates one assessment record and its associated findings atomically. This prevents a partial compliance record in which an assessment exists without its findings.

The trigger on `hardening_findings` rejects unusable findings before persistence.

## Failure Conditions

Hardening assessment systems must handle more than obvious misconfiguration.

### Disabled protection

A security control can be explicitly disabled. This is a direct compliance failure.

### Weak configuration

A control can be enabled but weaker than the baseline. Examples include a firewall profile allowing inbound traffic by default or a password minimum below the organizational requirement.

### Stale security intelligence

Defender may report active protection while its security intelligence is outside the allowed freshness window.

### Missing telemetry

A missing ASR record or firewall record cannot safely be treated as compliant. The implementations either report the missing state or interpret the missing ASR state as disabled for comparison.

### Invalid input

Hostnames, thresholds, enumerated states, and ASR identifiers are validated before they participate in assessment logic.

### Assessment failure versus non-compliance

A broken assessment process should not be reported as a compliant endpoint.

The C++ program explicitly separates successful assessments with findings from evaluation errors. The SQL function raises an exception when required endpoint telemetry is missing.

## Security and Production Considerations

The examples intentionally separate assessment from remediation.

Automatically applying security changes from an unverified telemetry source can create operational risk. A production implementation should authenticate the endpoint-management channel, validate the origin of telemetry, protect stored assessment data, restrict access to remediation capabilities, and preserve audit history.

Sensitive endpoint information should be minimized in logs. Hostnames, domain names, security events, and policy results can reveal organizational structure and should be subject to appropriate access controls.

PowerShell commands emitted by the examples should be reviewed in the context of the organization's management system before execution. A diagnostic command that reads state is materially different from a privileged command that changes state.

Application control and ASR policies require compatibility testing. Blocking executable content can interfere with legitimate workflows, and exceptions can weaken the intended security boundary if they are too broad.

Firewall policies should be evaluated against required business traffic before deployment. A secure default is useful only when operational dependencies have been identified and explicitly permitted.

## Performance Characteristics

The policy engines operate primarily on fixed collections of security controls.

For an endpoint with `D` Defender controls, `F` firewall profiles, `S` security-policy controls, `A` application-control controls, and `R` ASR rules, assessment cost is approximately:

`O(D + F + S + A + R)`

The number of controls is normally small and bounded, so endpoint assessment is effectively constant-time with respect to ordinary endpoint size.

The SQL system has different scaling characteristics because it operates over many endpoints and historical assessments. The indexes on endpoint assessment history and unresolved findings support common operational queries without indexing every column indiscriminately.

The partial index on unresolved findings is especially useful for security operations because resolved findings do not participate in the common open-finding workload.

## Governance Relationships

The security domains have distinct responsibilities:

| Domain | Primary responsibility | Typical decision |
|---|---|---|
| Microsoft Defender | Threat prevention and detection | Is endpoint protection active and current? |
| Windows Firewall | Network boundary | Which traffic is permitted by default? |
| Security Policies | Authentication and visibility | Are authentication and audit controls sufficiently strong? |
| Application Control | Executable trust | Which application execution modes are permitted? |
| ASR | Risky application behavior | Which high-risk behaviors should be blocked or audited? |

These controls are complementary.

For example, application control may restrict an executable while Defender provides malware detection, and the firewall may prevent the executable from reaching a network service if it somehow runs. Security auditing can then provide evidence about the process and authentication context.

A hardening program is strongest when these controls are evaluated as separate layers with explicit policy ownership rather than as one undifferentiated security score.
