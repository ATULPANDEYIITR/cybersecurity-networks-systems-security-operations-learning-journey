# Group Policy: Security Policies, Password Controls, and Workstation Restrictions

## Purpose and scope

Group Policy provides centralized configuration for managed Windows environments. Administrators define reusable collections of settings, associate those collections with directory scopes, and evaluate the resulting configuration for users or computers.

This laboratory models four closely related responsibilities:

- **Group Policy Objects (GPOs)** define the settings that administrators want to apply.
- **Security policies** establish controls for accounts, authentication behavior, auditing, and system security.
- **Password policies** establish password length, history, complexity, aging, and related account requirements.
- **Workstation restrictions** govern endpoint behavior, including firewall configuration, removable storage, automatic screen locking, and local-administrator installation privileges.

The distinction between a policy definition and its effective result is fundamental. A setting can exist in a GPO without affecting a particular workstation because the GPO is disabled, its link is disabled, its scope does not match, or another applicable policy has precedence.

The implementations use a fictional organization, `corp.example`, with an Engineering organizational unit and a managed workstation named `ENG-WS-042`. A domain security baseline establishes central controls, while an Engineering-specific GPO configures endpoint restrictions. A deliberately conflicting legacy GPO makes precedence visible.

## GPOs, scopes, and policy processing

A GPO is a collection of configuration settings. Linking a GPO to a scope determines where its settings can participate in policy processing. In a conventional Active Directory environment, policy links may exist at the site, domain, and organizational-unit levels.

The examples represent the scope hierarchy as:

- `North-Office`: site-level scope.
- `corp.example`: domain-level scope.
- `Engineering`: organizational-unit scope.
- `ENG-WS-042`: a computer associated with the site, domain, and Engineering OU.

The common site-domain-OU sequence is often described as LSDOU. It expresses the normal processing order, not an assurance that every setting from every linked GPO will win.

### Link order and precedence

When several applicable links configure the same setting, the resulting value depends on scope, link order, enforcement, inheritance, and the specific Windows policy-processing rules involved. Within a single scope, a link with order 1 normally has higher precedence than links with larger order numbers.

The code uses an explicit source record for each effective setting. This is important for troubleshooting: knowing that the firewall is enabled is useful, but knowing which GPO supplied that value makes the configuration explainable.

The examples mark `Domain-Security-Baseline` as enforced and configure a conflicting OU-level firewall exception. The intended result is that the normal child-scope exception does not override the enforced baseline setting.

An actual Windows environment requires careful testing of link order, inheritance, enforced links, security filtering, WMI filtering, loopback processing, and the distinction between computer and user policy. The simulations do not implement all of those mechanisms.

### GPO definitions and links are separate

A GPO can exist without being linked to a scope. A link can be disabled without deleting the GPO. A GPO can also be disabled independently of its links.

Keeping these states separate supports controlled changes. Administrators can prepare a GPO, validate its settings, and then enable its link for a limited scope. Disabling an experimental policy should remove its contribution to the simulated effective configuration without erasing the policy definition.

## Security policies

Security policy is broader than password requirements. It includes account controls, system protection, security auditing, and interactive logon configuration.

The examples configure a security baseline with an interactive logon banner, a defined account-lockout threshold, and a workstation firewall requirement. The Python and JavaScript implementations also identify disabled firewalls and disabled automatic screen locking as audit findings.

### Account protection

Account-lockout settings require particular care. A lockout threshold of zero may mean that lockout is disabled, depending on the relevant Windows policy. A nonzero threshold must be evaluated with the configured lockout duration and reset interval rather than treated as a complete security policy by itself.

Lockout can reduce repeated password-guessing attempts, but overly aggressive thresholds can allow attackers to disrupt legitimate access. A production policy should consider monitoring, recovery procedures, identity-provider behavior, and the operational needs of privileged accounts.

### Interactive logon controls

An interactive logon banner can communicate an organization's authorized-use notice before a user signs in. The setting does not itself provide authentication, prevent unauthorized access, or prove that the intended message appeared on every endpoint.

Effective-policy reporting must be paired with client-side verification to confirm that the configuration was actually processed.

### Auditing and security evidence

The SQL model records policy-related audit events with timestamps and structured JSONB details. This separates historical governance evidence from the current state of a GPO.

An audit event can describe a link change or an observed compliance result. It should not be interpreted as proof of successful policy application unless it records the relevant client-side evidence.

## Password policies

Password settings govern account credentials rather than workstation features. The implementations keep these settings in the password category and validate their allowed types and ranges.

| Setting | Meaning | Implementation behavior |
|---|---|---|
| Minimum password length | Minimum number of characters permitted by the policy | Enforced as an integer range in the policy models and checked against an organizational baseline |
| Password history | Number of previous passwords retained for reuse prevention | Stored as a bounded integer and audited against the baseline |
| Password complexity | Whether the selected complexity requirement is enabled | Represented as a Boolean setting |
| Maximum password age | Maximum age before a password must be changed under the configured policy | Zero is treated by the examples as no forced expiry |
| Minimum password age | Minimum time before another password change is permitted | Compared with the maximum age to identify inconsistent configuration |

The domain baseline uses a minimum length of 14 characters, a password history of 24 entries, enabled complexity, a minimum password age of one day, and no forced maximum-age expiry in this illustrative configuration.

These values represent an example organizational baseline rather than a universal compliance requirement. Password policy decisions should account for the organization's identity platform and current security guidance.

### Password candidate checks versus policy enforcement

The Python and JavaScript programs perform local checks on fictional password candidates. They test length and, when configured, the presence of lowercase letters, uppercase letters, digits, and non-alphanumeric characters.

These checks demonstrate validation logic. They do not establish that a candidate is acceptable to a real Windows account. They do not verify breached-password exposure, compare the candidate with an account's password history, evaluate every domain policy, or change an account password.

Real systems should use the appropriate identity service and avoid logging or persisting password values. A password must never be stored in reversible form for the purpose of auditing policy compliance.

### Password aging and history

Password settings are related but not interchangeable. Password history concerns reuse, minimum age concerns how frequently a password can be changed, and maximum age concerns the configured expiry interval.

The examples flag a minimum age that exceeds a nonzero maximum age. This is a useful consistency check, but it does not replace evaluation of the actual identity platform's behavior.

## Workstation restrictions

Workstation policies configure endpoint behavior rather than account credential requirements.

The Engineering GPO configures:

- Removable USB storage blocking.
- Automatic screen locking.
- A ten-minute screen-lock timeout.
- Restrictions on local-administrator installation.
- Removable-media auditing.

The domain baseline configures the firewall requirement. Keeping general security controls in the domain baseline and Engineering-specific restrictions in a separate GPO makes ownership and scope clearer.

### Removable storage

Blocking removable storage can reduce the risk of unauthorized data transfer and malware introduction. It can also interfere with legitimate operational workflows. Organizations should document exceptions, distinguish approved business devices from prohibited devices, and retain appropriate audit evidence.

A Boolean setting in a simulator represents the intended policy state. In Windows, the actual restriction may depend on specific device-installation, removable-storage, or access-control policy settings. A production implementation must map the intended control to the correct Windows policy.

### Screen locking

Automatic screen locking reduces the period during which an unattended workstation remains accessible. A timeout setting without an enabled screen-lock control may not provide the expected result, so policy auditing should evaluate both the enablement state and the timeout value.

### Local administrator restrictions

Preventing standard users from installing software with local-administrator privileges can reduce unauthorized software installation. It does not replace application control, patch management, endpoint detection, or privileged-access management.

The example treats the restriction as an intended configuration setting rather than proof that every executable or installation pathway is blocked.

## Python implementation

The Python script implements typed policy settings, GPO definitions, policy links, workstation assignments, and effective-policy evaluation using dataclasses, enumerations, dictionaries, and lists.

`PolicySetting` validates known setting names, value types, ranges, and category assignments. Invalid password-length values are rejected when a policy is constructed, before they can participate in evaluation.

`GroupPolicyEngine` evaluates matching site, domain, and OU links. It tracks the source GPO for every selected setting, excludes disabled GPOs, and supports a simplified representation of enforced links. The result contains effective values, source information, applied GPO names, and audit warnings.

`password_policy_findings` evaluates the selected password configuration against the example baseline. `demonstrate_password_validation` performs local checks on fictional candidate strings without storing credentials.

The self-tests verify that invalid settings are rejected, the enforced firewall baseline wins over the conflicting OU exception, the Engineering restriction is applied, and a disabled GPO no longer contributes its settings.

The Python model is designed for inspection and experimentation. It does not resolve the complete Windows policy hierarchy, security filtering, client-side extensions, or every interaction between user and computer policy.

## JavaScript implementation

The JavaScript program uses Node.js and the standard `EventEmitter` class to represent policy evaluation as an observable event.

`GroupPolicyObject` stores validated settings in a `Map`. Each setting record is frozen so a caller cannot mutate the stored record without using the validation method.

`PolicyRepository` manages the collection of GPO definitions and links. It validates scope types, GPO references, and link-order values, then selects links that match the workstation.

`PolicyEvaluator` calculates effective settings and emits an `evaluated` event. A listener records that an evaluation completed, while assertions verify the firewall precedence and Engineering restrictions.

This event-driven design is useful when evaluation must trigger additional application behavior, such as displaying a compliance result or sending an audit event. The event indicates that the simulator evaluated its data. It does not indicate that a real Windows client applied a policy.

The password audit and candidate-check functions are independent of the event mechanism. Their separation makes it possible to test credential-policy logic without running the entire policy workflow.

## C++ case study: endpoint governance engine

The C++ program presents a workstation governance case study using `std::map`, `std::vector`, and `std::set`.

`GroupPolicyObject` holds a named set of policy settings. It provides separate methods for Boolean and integer values, allowing the program to validate common ranges before a setting is stored.

`GovernanceEngine` maintains GPO definitions and their links. It finds links matching a workstation's site, domain, and OU membership, then orders them by scope depth and link order. During evaluation, it records the source of each effective value and prevents normal links from replacing settings established by enforced links.

The `Evaluation` structure separates effective configuration, source provenance, applied GPOs, and audit findings. This is useful for governance tooling because the resulting configuration and its explanation are available as distinct data structures.

The program deliberately introduces a conflicting legacy firewall policy. The engine must retain the enforced domain firewall setting despite the conflicting normal OU link. It then checks security invariants and demonstrates rejection of an invalid password-length value.

The model uses strings for stored setting values to keep the evaluation result simple, while the setter methods accept typed input. A production implementation could use `std::variant` for Boolean, integer, and text values, together with stronger schema validation and a more complete Windows precedence model.

The algorithm sorts matching links, then visits the settings in each applicable GPO. If there are \(L\) matching links and \(S\) total setting entries among those links, sorting costs \(O(L \log L)\) and setting evaluation costs \(O(S)\), excluding map-operation overhead.

## Java implementation: enterprise policy catalog

The Java program models policy configuration through domain types rather than embedding the entire workflow in `main`.

The `PolicySetting` record represents a setting's name, value, and category. Its compact constructor validates required fields and known value ranges. The `GroupPolicyObject` class maintains a collection of settings and an independent enabled state.

`PolicyLink` represents the relationship between a GPO and a directory scope, including link order, enablement, and normal or enforced behavior. `Workstation` represents the target endpoint and its directory placement.

`PolicyCatalog` manages definitions and links, identifies applicable policies, and evaluates their effective values. The returned `PolicyEvaluation` record contains immutable copies of the effective configuration, source mapping, applied GPO list, and findings.

This design separates policy storage from evaluation. That separation supports independent tests for validation, precedence, and audit logic and makes the evaluation service easier to replace or extend.

The program uses Java 17 language features and standard collections. The example demonstrates domain-oriented modeling and immutable result records, but it does not implement a production directory integration, Windows client-side processing, or remote policy deployment.

## SQL data model and governance queries

The PostgreSQL script models policy governance relationally. It uses primary keys, foreign keys, unique constraints, check constraints, indexes, an enumerated type system, a trigger, and a view.

### Relational structure

| Table | Responsibility |
|---|---|
| `repositories` | Identifies the managed directory environment |
| `policy_scopes` | Stores site, domain, and OU scopes |
| `group_policy_objects` | Stores named policy definitions and their enabled states |
| `policy_settings` | Stores typed settings belonging to each GPO |
| `policy_links` | Connects GPOs to scopes and stores link order and enforcement mode |
| `workstations` | Registers endpoints and their site and domain assignments |
| `workstation_ou_memberships` | Represents workstation membership in organizational units |
| `directory_users` | Stores example user identities and account state |
| `security_groups` | Defines directory security groups |
| `user_group_memberships` | Relates users to groups |
| `policy_audit_events` | Retains structured governance event records |

Foreign keys prevent links from referring to nonexistent GPOs or scopes. Unique constraints prevent duplicate directory names, GPO names within a directory, duplicate setting names within one GPO, and duplicate workstation names within a directory.

### Typed settings and database constraints

`policy_settings` uses a value-type discriminator with separate Boolean, integer, and text columns. Its check constraint ensures that exactly the appropriate value column is populated for each type.

Other constraints enforce password-setting ranges and category requirements. The `validate_policy_setting_category` trigger adds category checks for known workstation and password settings.

Database constraints complement application validation. They protect stored data even when a row is inserted through a client that does not use the same validation code as the Python, JavaScript, C++, or Java program.

### Effective-policy view

`workstation_effective_policy` identifies links applicable to each workstation, joins their settings, and uses window functions to select a candidate effective setting.

The query records the source GPO along with the selected value. This allows the caller to investigate both configuration and provenance.

The view is an educational model of precedence. It prioritizes enforced entries, then considers scope depth and link order. The precise handling of normal and enforced links in Windows is more nuanced than this simplified ordering. The SQL view should not be used as a substitute for native Windows policy diagnostics.

### Audit and endpoint queries

The script includes queries for:

- Effective setting values and source GPOs.
- Password length and history values below the example baseline.
- Endpoint controls related to firewalls, removable storage, screen locking, local administrator restrictions, and removable-media auditing.
- The set of linked policies participating in a workstation evaluation.

The sample audit query evaluates stored effective values. It does not independently verify whether a workstation has received or applied the selected settings.

### Transactions and operational safety

The script runs schema creation and sample-data insertion within a transaction. The initial schema drop is destructive, so it is intended for a dedicated learning database.

The indexes target link lookup, setting lookup, workstation OU membership, and chronological audit queries. Their usefulness depends on data volume and query plans; production deployments should validate them with representative workloads.

## Understanding the relationship between the policy layers

A GPO defines settings, and a link determines the scope in which the definition participates. Policy processing determines the effective configuration for a target computer or user.

Security policy, password policy, and workstation restrictions describe different classes of settings. They can be packaged together in a GPO, but their purpose and validation requirements remain distinct.

For example, an enabled firewall setting does not establish a password baseline, and a strong password baseline does not prevent unauthorized removable-storage use. Each control requires an appropriate setting, scope, precedence evaluation, and verification method.

An effective configuration is also different from observed compliance. A policy model may calculate that a workstation should have its firewall enabled, but the workstation may be offline, unable to process the policy, affected by an unsupported setting, or in a state that has not yet been verified. Governance systems should distinguish intended policy, calculated effective policy, successful client application, and independently observed compliance.

## Limitations and production considerations

The programs model core concepts rather than the complete Windows Group Policy platform. Their precedence algorithms do not implement every detail of Active Directory, security filtering, WMI filters, user-policy loopback, policy refresh, replication, client-side extensions, or policy-specific processing behavior.

The examples also use a small set of illustrative controls. Actual Windows settings may require multiple registry-backed values, administrative templates, security options, device-control rules, or other policy-specific structures.

A production governance service should maintain versioned policy definitions, identify the responsible administrator, record approvals for sensitive changes, preserve an audit trail, validate target scopes before deployment, and verify results through trusted client-side evidence. Sensitive changes should be tested on a limited set of endpoints before wider deployment.

Password controls require particular care. Local regular-expression checks are not a substitute for identity-provider validation, and policy evaluation should never require logging plaintext credentials. The effective settings reported by these programs are simulation results, not evidence that a real password or workstation satisfies every security requirement.
