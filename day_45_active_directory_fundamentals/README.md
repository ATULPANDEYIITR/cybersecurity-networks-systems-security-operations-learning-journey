# Active Directory Fundamentals: Domains, Controllers, Identities, Groups, OUs, and Policies

## Scope and technical model

Active Directory Domain Services (AD DS) is Microsoft's directory service for centrally managing identities, computers, authentication, and directory-based administration in Windows environments. Its logical structure and administrative controls solve different problems: a domain defines an administrative and identity boundary, domain controllers provide directory services, users and computers represent security principals, groups organize access, organizational units organize delegated administration and policy targeting, and Group Policy Objects configure supported Windows settings.

The five implementation files use an educational directory model to examine these relationships. They do not implement AD DS, LDAP, Kerberos, Windows access tokens, or the complete Group Policy processing engine. Their policy and replication calculations are deliberately simplified. Production behavior must be verified against the actual Windows Server environment.

## Directory architecture

A typical enterprise directory contains a forest, one or more domains, organizational units, directory objects, and domain controllers. A forest establishes a common schema and configuration context and normally provides transitive trust relationships between its domains. A domain maintains its own directory partition, domain identities, domain-specific policies, and security administration.

The DNS name `corp.example.com` corresponds to the distinguished name `DC=corp,DC=example,DC=com`. Distinguished names identify directory objects within the directory naming hierarchy. An OU named `Engineering` under this domain has a distinguished name such as `OU=Engineering,DC=corp,DC=example,DC=com`.

| Component | Responsibility | Important distinction |
|---|---|---|
| Domain | Organizes domain identities and domain-level administration | A domain is not simply an OU or a DNS zone |
| Domain controller | Hosts AD DS and serves directory and authentication requests | Multiple controllers can serve the same domain |
| User | Represents an individual or service identity | A user object does not automatically authorize access to every resource |
| Security group | Aggregates security principals for authorization | Group membership and resource permissions are separate relationships |
| Organizational unit | Organizes objects and supports delegated administration and policy linking | OU placement is not, by itself, an access grant |
| Group Policy Object | Stores user and computer configuration settings | A GPO link determines scope; a setting's effective value depends on processing rules |
| Global Catalog | Supports forest-wide searches and selected logon-related lookups | It is not a substitute for every domain controller function |
| Operations master role | Assigns particular directory operations to designated role holders | The roles are not interchangeable with ordinary replication responsibilities |

## Domain controllers, DNS, and replication

A domain controller provides directory operations and participates in authentication. Clients depend on correctly configured DNS to locate domain services. A domain controller can also hold one or more Flexible Single Master Operations (FSMO) roles. These include the Schema Master and Domain Naming Master at the forest level and the RID Master, PDC Emulator, and Infrastructure Master at the domain level.

Multiple controllers improve availability and distribute directory requests. AD DS uses multi-master replication for many directory changes, with particular operations governed by FSMO roles. Replication latency means a change observed on one controller may not be immediately visible on another. A replication failure can therefore produce different observations across controllers.

The Python, JavaScript, C++, and Java programs record a controller's site, selected roles, reachability, and observed revision. Their revision-lag calculations illustrate the concept of convergence only. They do not reproduce AD replication metadata, invocation IDs, update sequence numbers, site-link schedules, conflict resolution, or replication diagnostics. A production investigation needs actual controller health and replication evidence rather than a synthetic revision counter.

## User and computer identities

A user account includes attributes used for identification, directory lookup, and administrative classification. Common attributes include `sAMAccountName`, `userPrincipalName`, department, distinguished name, and account-control state. The sAMAccountName traditionally has a maximum length of 20 characters. A UPN commonly follows the form `user@domain.example`, although the UPN suffix does not have to match the domain's DNS name.

A computer account represents a domain-joined computer. Its directory identity supports the computer's domain relationship and secure-channel operations. A computer account, a local Windows account, and a domain user are distinct identities.

Account state affects authentication and access decisions. Disabled and locked accounts should not be treated as normal enabled principals. Password policy, account lockout, MFA, and authentication protocols are related but distinct controls. MFA enforcement depends on the authentication architecture and policy configuration; registering an MFA method does not itself guarantee that every authentication path requires it.

The Python implementation demonstrates uniqueness checks, user creation, account locking after repeated failed attempts, and audit events. Its SHA-256 digest is only an illustration of one-way transformation. It is not a suitable replacement for AD DS password storage, which is managed by the directory service. Production authentication should use supported Windows authentication mechanisms and must not expose or retain plaintext passwords in application logs.

The JavaScript implementation uses event emission to separate directory changes from their observers. A listener can count or forward audit events without embedding notification logic into each administrative method. This event stream is a local application mechanism, not an AD DS change notification subscription.

## Security groups, scope, and nested membership

Security groups simplify authorization by assigning permissions to groups rather than maintaining separate access lists for every user. A user can be a direct member of multiple groups, and groups can contain other groups where the domain and group-scope rules permit it.

The three principal security-group scopes have different membership and permission purposes:

- **Global groups** commonly collect accounts with similar roles from their own domain. They are frequently used to represent business or job functions.
- **Domain local groups** commonly represent permissions needed for resources in their own domain. They are frequently used to aggregate role groups before assigning permissions to a resource.
- **Universal groups** can aggregate membership across domains in a forest and are useful where cross-domain membership is required.

A common AGDLP design uses accounts in global groups, global groups in domain local groups, and domain local groups to receive permissions. Forest-wide scenarios may use universal groups where appropriate. The correct group nesting depends on domain boundaries, resource locations, and scope constraints.

Distribution groups serve messaging and distribution purposes rather than Windows security authorization. The implementations distinguish distribution groups from security groups so that an object intended for communication cannot accidentally become an authorization principal.

The programs calculate effective group membership by traversing membership edges. A visited set prevents repeated traversal, while cycle detection rejects membership relationships that would cause recursive nesting. The SQL implementation uses a recursive common table expression and a trigger to validate nested membership. These controls are useful for the educational model, but they do not replace the full group-scope validation and token-construction behavior of AD DS.

Group membership alone does not grant every permission. A resource must grant the appropriate rights to a security principal, and the account must be eligible to access that resource. The example production deployment resource is authorized through the `Production-Administrators` group, not through the user's OU.

## Organizational units and delegated administration

OUs provide a hierarchy for organizing directory objects. Administrators can use that hierarchy to delegate selected administrative tasks and to define Group Policy scope. An OU can contain users, groups, computers, and child OUs.

A useful enterprise layout separates operational responsibilities. For example, `Engineering` can contain standard engineering accounts, while `Privileged` contains accounts subject to more restrictive administrative procedures. Separate OUs can be used for workstation classes, servers, service accounts, or organizational units that require different configuration policies.

An OU is not a security group. Moving a user into an OU changes its directory placement and can change which GPOs apply, but it does not automatically grant file-share, application, or deployment permissions.

The implementations construct distinguished names from OU parent relationships, validate parent existence, and reject accidental deletion of protected OUs. The SQL schema uses a self-referencing foreign key for the hierarchy. The protection trigger illustrates a database-level safeguard. Actual AD DS deletion protection and delegated permissions must be configured and tested in Windows Server.

## Group Policy Objects and policy processing

A Group Policy Object contains user-configuration and computer-configuration settings. It can be linked to a site, domain, or OU. A link defines where a GPO participates in processing; the GPO's existence alone does not mean that its settings apply to every directory object.

For domain and OU processing, the common LSDOU sequence refers to Local, Site, Domain, and Organizational Unit policies. In a simplified normal processing case, later applicable settings can override earlier conflicting settings. OU nesting, link order, enforcement, inheritance blocking, security filtering, WMI filtering, disabled links, and disabled configuration sections can change the result.

An enforced link resists normal inheritance blocking and the usual override behavior of descendant links for settings that conflict with it. A child OU's block-inheritance setting can prevent normal inheritance from higher scopes, but it does not normally prevent enforced policies from applying. A policy linked directly at a scope can also be affected by the order of links at that scope.

The four programs that calculate policy values use a deliberately simplified precedence algorithm. They model ancestor scopes, link order, enforced links, disabled policies, and setting overrides. They do not fully implement LSDOU, block inheritance, security filtering, WMI filters, loopback processing, slow-link behavior, user-versus-computer processing, or all precedence edge cases. The Python `PolicyLink` type records a block-inheritance field for modeling purposes, but its evaluator does not implement complete inheritance-blocking semantics. The JavaScript, C++, and Java evaluators likewise do not claim complete Group Policy equivalence. The SQL example demonstrates an ancestor query and an explicit ranking rule, rather than an authoritative Resultant Set of Policy engine.

### Policy settings in the laboratory

| Setting | Directory-administration purpose |
|---|---|
| Minimum password length | Represents a password policy requirement |
| Lockout threshold | Models the number of failed attempts that can trigger a lockout policy |
| Require MFA | Represents an authentication control whose enforcement depends on the authentication system |
| USB storage allowed | Models a computer configuration restriction |
| Screen-lock interval | Represents a workstation security setting |
| Firewall enabled | Represents a host security baseline setting |

The sample baseline establishes restrictive default values, while the Engineering workstation GPO proposes different values for selected settings. The enforced baseline demonstrates why a descendant policy cannot necessarily override a higher-scope enforced setting.

A policy value stored in a GPO is not proof that a client has successfully applied the setting. Real systems can be affected by scope filtering, permissions, connectivity, client-side extensions, operating-system support, and processing errors. Verification should distinguish configured values from effective client state.

## Python implementation

The Python script defines directory objects as dataclasses and organizes them in an `ActiveDirectoryDomain` service. It maintains GUID-based object references, case-normalized identity indexes, group membership sets, OU parent relationships, GPO links, and an audit event list.

The user-creation operation checks the sAMAccountName and UPN indexes before inserting a new object. Group membership is represented by object GUIDs so that display names do not become identity keys. Nested membership is traversed with a stack and a visited set, and a proposed membership cycle is rejected before the relationship is stored.

The authentication demonstration maintains a failure counter and changes an account's state when the configured threshold is reached. Its behavior illustrates account-state transitions rather than a production login protocol. The policy evaluator gathers ancestor OUs and applies linked settings using its simplified precedence rule. The replication report compares synthetic controller watermarks with the domain revision.

The audit log records administrative and authentication events with a timestamp and revision. It is suitable for demonstrating traceability, but it is not tamper-resistant storage and should not be used as a substitute for Windows security auditing.

## JavaScript implementation

The JavaScript file models directory changes with classes and an `EventEmitter`. `ActiveDirectoryDomain` publishes a `directory-event` after recording each mutation. This separation allows other application components to observe directory changes without coupling the observer to user, OU, group, or GPO creation.

JavaScript `Set` objects represent group members and effective memberships. The traversal tracks visited identifiers, making repeated nested-group paths safe to process. The policy object freezes a copy of its initial settings to reduce accidental mutation, although a complete production system would also need stronger encapsulation for the remaining domain state.

The file uses assertions to verify expected failure behavior and exposes its main classes through CommonJS exports. Running the file directly executes the demonstration; requiring the module from a test can reuse the domain service. Its event stream is local to the Node.js process and does not provide durable messaging, cross-controller replication, or transactional persistence.

## C++ case study: deterministic directory governance

The C++ program uses a distributed engineering organization as its case study. It creates a domain, registers controllers in the Lucknow and Delhi sites, organizes engineering and privileged OUs, and creates separate user and group records.

The governance service maintains ordered maps for directory objects and policy definitions. Ordered containers make demonstration reports deterministic, which helps compare expected policy and membership results. The nested group graph is traversed recursively with a visited set. The membership-validation routine rejects self-membership and cycles before adding a new edge.

The GPO evaluator constructs the ancestor chain from the target OU to the root, reverses it into parent-first order, and evaluates the links at each scope. It sorts links by link order and tracks enforced values separately from ordinary values. This illustrates precedence as a state-combination problem, rather than treating each GPO as an independent collection of settings.

The implementation checks policy ranges and accepted Boolean representations before storing a GPO. It also distinguishes domain-controller observations from current domain revisions. The resulting lag report is an illustrative operational indicator, not a claim that a real controller's replication state can be determined from an application counter.

The program uses standard C++17 containers and exceptions. Membership traversal is proportional to the group graph explored; a large hierarchy can make repeated cycle checks expensive. A production service would consider indexed membership lookups, transactional updates, audit durability, concurrency control, and comprehensive validation of group scope across domains.

## Java implementation: enterprise domain services

The Java program uses explicit domain types for users, groups, OUs, controllers, GPOs, policy links, and audit events. These types keep identity attributes and policy state separate. Enumerations represent account status, group scope, group type, and policy-setting names, preventing arbitrary strings from representing every domain concept.

The `DirectoryService` owns the maps that enforce identity uniqueness and the operations that mutate directory state. The user index is keyed by a normalized sAMAccountName, while the distinguished-name index identifies objects by their directory location. Membership is represented by UUID references, avoiding dependence on display names.

The authorization method first verifies that the principal and required group exist and that the principal is enabled. It then checks transitive security-group membership. This establishes the difference between identity state, group membership, and the resource's required group.

The GPO model uses an `EnumMap` for settings and validates values when a policy is constructed. The policy evaluator returns an unmodifiable result so callers cannot change its output map. Records represent immutable audit events and controller status snapshots. This approach makes service output explicit and reduces accidental modification of the reporting data.

The implementation's validation and immutable views improve local correctness, but the service is not a complete enterprise directory implementation. Production use would require authentication integration, authorization boundaries for administrative operations, persistence transactions, concurrency safeguards, secrets handling, and actual directory-service integration.

## SQL data model and database enforcement

The PostgreSQL script defines a dedicated `ad_lab` schema and creates relational tables for domains, OUs, controllers, operations master roles, users, groups, group memberships, GPOs, settings, links, resources, authentication events, and administrative audit events.

Foreign keys preserve relationships between domains and their objects. Unique constraints protect domain names, user account names, UPNs, group identities, and OU names within the defined scope. Check constraints restrict valid account names, policy-setting names, values, and membership row shapes.

The `group_memberships` table permits exactly one member type per row. A membership can refer to a user or a nested group, but not both. Partial unique indexes prevent duplicate user-to-group and group-to-group membership edges. The trigger verifies that the target is a security group, checks domain consistency, and rejects cycles through a recursive query.

The OU hierarchy uses a self-referencing foreign key. A deletion trigger rejects deletion of OUs whose protection flag is enabled. The sample GPO settings are stored as JSONB values, while the allowed setting names and expected value types are constrained by relational checks.

The `effective_user_security_groups` view expands nested membership with a recursive common table expression. The policy query constructs the target OU's ancestor chain and ranks applicable GPO settings. The resource authorization query checks effective security-group membership instead of inferring permission from OU placement.

The sample transaction creates the schema, loads representative objects, and evaluates policy, membership, resource access, controller observations, and audit data. Its invalid policy example uses a nested exception block to show database-level constraint enforcement without aborting the rest of the demonstration.

The SQL model intentionally does not represent every AD DS schema class, cross-domain trust rule, SID, access control entry, Kerberos ticket, replication metadata structure, or Windows policy-processing condition. PostgreSQL constraints enforce the model's rules; they do not make PostgreSQL an AD DS server.

## Administrative security and failure handling

Directory administration should follow least privilege. Administrative accounts should be separated from ordinary daily-use identities where the operational model permits it. Privileged groups should have narrowly defined membership and resource permissions, and membership changes should be auditable.

The following distinctions are important during troubleshooting:

- A user may authenticate successfully but still lack the security group required by a resource.
- A group membership change may not be visible on every domain controller immediately because of replication latency.
- A user can be in the correct OU while the expected GPO is not applied because the link is disabled, filtering excludes the object, or policy processing fails.
- A GPO can contain the expected setting while the effective client configuration differs because of precedence or client-side processing.
- A domain controller can be reachable while a specific directory operation, DNS lookup, secure channel, or replication relationship is unhealthy.
- A disabled account, a locked account, an incorrect password, and a missing authorization group represent different failure conditions and require different investigation paths.

The code models selected validation failures and records their causes. It does not attempt to simulate every Windows event, protocol exchange, or permission evaluation. A production incident response should correlate actual domain-controller logs, client-side Group Policy results, DNS resolution, replication diagnostics, account status, and resource permissions.

## Performance and production design considerations

Directory operations often rely on indexed identity attributes and hierarchical queries. Normalized account-name indexes reduce duplicate checks to near-constant expected lookup time. In contrast, scanning every object for each distinguished-name check becomes expensive as the directory grows. Production directory services provide indexing and specialized query mechanisms that should be used instead of repeatedly scanning an entire in-memory collection.

Transitive group membership can require visiting many membership edges. A visited set prevents repeated processing and infinite traversal in malformed graphs, while explicit cycle prevention rejects a problematic relationship at insertion time. Concurrent membership changes require transactional or directory-service guarantees to prevent two individually valid changes from creating an invalid combined state.

GPO evaluation is sensitive to scope and precedence. An administrator should distinguish the stored configuration, linked scope, filtered applicability, and resultant client configuration. A simplified evaluator is useful for explaining these relationships but cannot safely predict every production policy outcome.

Audit records should be retained with controlled access, reliable timestamps, and appropriate integrity protections. Controller monitoring should use actual replication and service-health signals. Authentication should rely on supported protocols, appropriate password handling, and the organization's established MFA architecture.

The principal architectural distinction remains essential: the domain organizes identity administration, controllers provide directory services, users and computers identify principals, security groups support access decisions, OUs provide organization and delegation boundaries, and Group Policy controls applicable configuration. These mechanisms interact, but none should be treated as a substitute for the others.
