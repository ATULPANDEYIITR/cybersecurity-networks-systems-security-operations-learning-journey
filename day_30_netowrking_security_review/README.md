# Networking Security Review

## Scope

This repository section models a defensive networking security review around four connected areas:

- network attack surface
- exposed services
- insecure protocols
- network segmentation fundamentals

The three implementations use the same security domain but deliberately approach it differently. Python provides an inventory and assessment toolkit, JavaScript models an event-driven review pipeline, and C++ implements a more strongly typed governance engine for a multi-zone enterprise network.

The examples are static simulations. They do not perform network discovery, port scanning, exploitation, credential testing, packet interception, or interaction with systems outside the supplied data.

## Security Review Model

A useful network review separates questions that are often incorrectly combined.

**Attack surface** asks what reachable components create opportunities for unwanted interaction. An asset may have many services, but the relevant question is which of those services cross meaningful trust boundaries.

**Exposed services** focus on service endpoints that are reachable from a boundary such as the Internet, a partner network, a user segment, or a management network. Exposure is a property of reachability and policy, not merely of a port number.

**Insecure protocols** concern the protection properties of the communication mechanism. Encryption, authentication, integrity protection, protocol age, configuration, and deployment context all matter. A port by itself does not determine whether communication is secure.

**Segmentation** establishes separate trust zones and controls communication between them. Separate subnets or VLANs are not sufficient by themselves. The security benefit comes from policy enforcement that restricts traffic to documented and necessary flows.

The relationship can be expressed as:

    Asset
       |
       +-- Service
       |      |
       |      +-- Protocol security
       |      +-- Authentication
       |      +-- Encryption
       |
       +-- Network zone
              |
              +-- Reachability
              +-- Inter-zone policy
              +-- Trust boundary

A mature review therefore considers both the endpoint and the path through which another system can reach it.

## Network Attack Surface

The attack surface is the collection of reachable interfaces, services, protocols, administrative paths, and other network-facing components through which interaction with an environment is possible.

The review should distinguish between an installed service and an exposed service. A database listening on a private application segment has a different exposure profile from the same database being reachable from an untrusted external network.

The Python implementation represents every service with properties such as:

- port
- transport
- protocol
- purpose
- authentication state
- encryption state
- Internet exposure
- protocol-security classification

The `AttackSurfaceAnalyzer` converts those properties into findings rather than treating every service as inherently vulnerable.

The sample inventory deliberately includes a public HTTPS service, an Internet-facing SSH service, a legacy FTP service, an internal application API, and an internal database service. This allows the analysis to distinguish public application traffic from administrative access, legacy communication, and internal application-to-database communication.

### Attack-surface reduction

Attack-surface reduction is primarily about removing unnecessary reachable functionality.

For example, an application gateway may legitimately expose HTTPS because users require public access. An administrative SSH interface may have a different requirement and should not automatically inherit the same Internet exposure simply because the host already needs HTTPS.

The Python analyzer identifies a large collection of Internet-facing services as an attack-surface review condition. This is not a claim that a specific number of services constitutes a vulnerability. It is a signal that the public boundary should be reviewed for business justification and lifecycle necessity.

Useful review questions include:

- Is the service required for the system's documented business role?
- Is it intended to be reachable from the Internet?
- Can access be restricted to a smaller set of networks?
- Is an administrative interface unnecessarily sharing the public boundary?
- Is the service still required, or is it a legacy dependency?
- Does the service expose a higher-value asset than its business function requires?

The central design principle is least exposure rather than simply fewer ports.

## Exposed Services

A service becomes particularly important during a security review when it crosses a trust boundary.

The examples use `internetExposed` as an explicit inventory property. This prevents the assessment from assuming that every service is publicly reachable merely because a port is associated with it.

The Python and JavaScript implementations identify Internet-facing services separately from internal services. The C++ implementation performs the same distinction through a strongly typed `Service` structure.

Exposure should be evaluated together with:

- source networks
- destination networks
- service port
- transport protocol
- authentication
- encryption
- business purpose
- asset criticality
- segmentation policy

An Internet-facing HTTPS endpoint may be an intended part of a public application. An Internet-facing database administration service could represent a substantially different boundary decision.

### Administrative exposure

Administrative protocols deserve separate treatment because they provide privileged operational access.

The C++ case study specifically flags SSH and RDP rules that cross into highly trusted zones. This is different from identifying FTP as an insecure protocol. FTP concerns the communication mechanism and its protection characteristics, while an administrative SSH rule concerns where privileged management traffic is allowed to originate.

A dedicated management segment provides a clearer trust boundary for administration. User endpoints should not automatically receive the same network-level access as controlled administrative systems.

## Insecure Protocols

Protocol security cannot be determined reliably from the port number alone.

The implementations model four protocol-security classifications:

| Classification | Meaning in the review model |
|---|---|
| `secure` | The service is expected to use protected communication and the inventory requires encryption |
| `legacy` | The mechanism may still exist for compatibility but requires migration or compensating controls |
| `insecure` | The mechanism lacks important protection properties and should not be treated as an acceptable public communication method |
| `context-dependent` | Security depends on deployment configuration and surrounding controls |

The sample FTP service is intentionally modeled as insecure because its traditional protocol design does not provide the same confidentiality and integrity properties expected from modern protected file-transfer mechanisms.

HTTP is also represented as an insecure protocol in the Python inventory when it is used without transport encryption. The important distinction is that the review does not merely say "port 80 is bad"; it records that the service lacks encryption and evaluates its exposure and authentication properties.

The PostgreSQL service demonstrates the opposite situation. A database protocol is not automatically safe simply because it is an internal protocol. Its security depends on authentication, encryption configuration, authorization, network reachability, and application architecture. The example therefore marks the database connection as protected and internal rather than treating the database port itself as a security guarantee.

### Authentication and encryption

Authentication answers who or what is allowed to establish or use a service.

Encryption protects communication against unauthorized observation and, depending on the protocol and configuration, helps provide integrity protection.

These controls address different problems. A service can require authentication while still transmitting sensitive data without adequate confidentiality. Conversely, encryption does not by itself establish that the connecting party is authorized to perform a particular operation.

The assessment therefore stores both properties independently.

## Network Segmentation Fundamentals

Segmentation divides a network into security zones with deliberately controlled relationships.

The case study uses the following conceptual architecture:

    Internet
        |
        v
       DMZ
        |
        v
    Application
        |
        v
     Database

    User --------------------> Management
       \
        \ controlled access only

The trust values in the examples are not universal industry ratings. They are local policy metadata used by the demonstration engine to distinguish ordinary endpoint networks from more protected application, database, and management zones.

### DMZ

The DMZ represents a boundary for systems that need some form of external reachability.

The public web gateway is placed in the DMZ rather than directly into the database or application-data segment. The policy then permits HTTPS from the Internet into the DMZ and HTTPS from the DMZ into the application layer.

This creates an explicit chain of permitted communication instead of treating the entire internal network as reachable after the first boundary is crossed.

### Application segment

The application segment contains services that perform business processing.

The example permits the DMZ to communicate with the application tier through HTTPS. The application tier is then permitted to access the database through PostgreSQL on port 5432.

This creates a service-specific relationship:

    DMZ -- HTTPS --> Application
    Application -- PostgreSQL --> Database

The database does not need to be generally reachable from the Internet or from ordinary user endpoints.

### Database segment

The database segment represents a higher-trust destination containing transactional data.

The C++ policy engine treats protected zones as requiring explicit inbound flows. The application-to-database relationship is therefore represented as an approved exception rather than a broad "internal network can access database" assumption.

This is an important segmentation property: the network should express which application dependency is required instead of allowing an entire source population to access the destination.

### Management segment

Administrative access is separated conceptually from ordinary application traffic.

The sample policy intentionally contains a broad user-to-management SSH rule. The C++ and JavaScript implementations flag this relationship because an employee endpoint zone is not equivalent to a controlled administrative zone.

A management design can instead require administration through explicitly authorized hosts or a controlled administrative path. The precise implementation depends on the organization's architecture, but the security principle is that privileged network access should have a narrower source population and stronger governance than ordinary user traffic.

## Flow Policy

A segmentation policy can be represented as a tuple:

    source zone
    destination zone
    service
    port
    allowed or denied
    business justification

The Python `FlowRule`, JavaScript rule objects, and C++ `FlowRule` structure all implement this model.

For example:

    application -> database -> PostgreSQL -> 5432 -> allowed

contains more security meaning than:

    internal -> internal -> allowed

The first rule identifies the source trust zone, destination trust zone, application protocol, port, and intended relationship.

The implementations intentionally avoid inventing broad default-allow behavior for protected destinations. A missing explicit rule is treated as absent from the approved policy model.

In production environments, actual enforcement may occur across multiple firewalls, cloud security groups, network ACLs, host firewalls, service meshes, routers, proxies, or other control points. A documentation model must therefore be reconciled with the controls that actually enforce it.

## Python Implementation

The Python program is designed as a compact defensive assessment toolkit.

`Service` represents a network service and validates:

- valid TCP or UDP ports
- supported transport
- non-empty protocol names
- consistency between a secure classification and encryption

`Asset` combines service information with hostname, address, zone, ownership, business role, and criticality.

`AttackSurfaceAnalyzer` examines Internet-facing services and produces findings for risky public protocols, unauthenticated public services, large public endpoint surfaces, and high-criticality assets located in ordinary user zones.

`NetworkSegment` models a security zone using a CIDR and trust level.

`FlowRule` models an explicit source-to-destination service relationship.

`SegmentationEngine` evaluates whether protected zones have explicit inbound policy and separately identifies administrative protocols crossing protected boundaries.

The report layer produces JSON without requiring an external package. The script also contains `unittest` tests covering invalid ports, inconsistent encryption metadata, insecure public services, expected application-to-database policy, and the intentionally broad management SSH rule.

The resulting report is written to `network_security_review_report.json`.

The Python implementation therefore demonstrates the progression from raw inventory data to validated security findings and a machine-readable report.

## JavaScript Implementation

The JavaScript program emphasizes an event-driven review architecture.

`NetworkAsset` represents inventory objects and performs configuration validation.

`AttackSurfaceReview` uses JavaScript `Map` and array operations to create an asset index and flatten service records into a reviewable collection. This is useful when a security system needs to process a larger inventory without repeatedly searching an unindexed list.

`SegmentationPolicy` represents zones and traffic rules. Its `allows()` method demonstrates explicit policy evaluation, while `evaluate()` checks protected-zone relationships and administrative protocols.

`ReviewPipeline` extends Node.js `EventEmitter`. The review emits lifecycle events such as `inventory-validation`, `attack-surface-analysis`, and `segmentation-analysis`. An asynchronous boundary using `setImmediate()` models a pipeline in which individual review stages may later become asynchronous operations.

The JavaScript implementation also demonstrates structured error handling through `ConfigurationError`. Configuration problems are separated from ordinary security findings, which is important in real assessment systems because an invalid inventory should not silently become a clean security result.

The report is written to `network-security-review.json` using Node.js's standard `fs/promises` API.

## C++ Case Study

The C++ program models an enterprise network governance engine.

The scenario contains:

- an Internet boundary
- a DMZ
- an employee user segment
- an application segment
- a database segment
- a management segment

The inventory includes a public HTTPS gateway, Internet-facing FTP, an internal HTTPS API, and an internal PostgreSQL database.

`NetworkInventory` owns the assets and builds a `std::map` index by asset identifier. It also validates duplicate addresses and duplicate asset identifiers.

`ExposureReview` evaluates public service exposure. It distinguishes protocol problems from unauthenticated exposure and from placement problems involving high-criticality services.

`SegmentationPolicyEngine` stores zones in a map and evaluates explicit flow relationships. It checks protected destinations and identifies administrative SSH or RDP paths crossing protected boundaries.

`SecurityReviewEngine` composes those two assessment domains into a single review result. Findings are sorted by risk score and then by asset and title to produce deterministic output.

The report writer produces dependency-free JSON. A dedicated JSON escaping function is used so evidence containing quotation marks or control characters cannot corrupt the generated report.

The C++ design uses ownership explicitly. The main review engine owns its inventory and segmentation policy instead of relying on global state. Validation errors are handled through typed exceptions, allowing configuration failures to be distinguished from unexpected runtime failures.

## Review Findings and Risk Scoring

The scores in these implementations are demonstration values, not universal vulnerability ratings.

The purpose of the score is to show how a review engine can combine characteristics such as exposure, authentication state, criticality, and protocol classification into a deterministic finding severity.

A real assessment should use an organization's approved risk methodology. Factors commonly considered include:

- asset business impact
- data sensitivity
- Internet or partner exposure
- privilege level
- exploitability
- compensating controls
- monitoring capability
- likelihood
- potential operational impact
- existing segmentation

A service should not receive a high rating solely because it uses a particular port. The surrounding exposure and controls determine the security significance.

## Edge Cases

### A service exists but is not externally reachable

An internal service can be legitimate even when its protocol would be unsuitable for public exposure. The review should distinguish protocol suitability from boundary exposure.

### An encrypted protocol is exposed unnecessarily

Encryption reduces certain communication risks but does not justify unnecessary exposure. A service can use strong encryption and still have an unnecessarily broad network boundary.

### A service is authenticated but not encrypted

Authentication does not automatically protect transmitted data. The review therefore stores authentication and encryption independently.

### A database is reachable only from its application tier

This is a strong segmentation pattern in the model because the database flow is explicitly limited to an application relationship.

### A required flow has no policy rule

The model treats the absence of an approved flow as missing policy rather than silently assuming that the traffic should be allowed.

### A protected zone has many permitted sources

Multiple explicit rules can still represent excessive exposure. Explicit policy is necessary, but policy quality also requires reviewing whether every permitted source is actually required.

### Administrative access originates from user networks

The example flags this separately from protocol security. SSH may be encrypted and authenticated while the source-to-destination relationship is still too broad for the intended trust model.

### Duplicate inventory entries

The Python and C++ implementations reject duplicate identifiers or addresses where those duplicates would make assessment results ambiguous. An assessment system that silently accepts duplicate records can produce misleading attack-surface counts.

## Common Review Mistakes

A port number should not be treated as a complete security assessment. Port 443 does not guarantee that an application is secure, and port 22 does not automatically mean that an SSH deployment is appropriate for a particular boundary.

A subnet should not be treated as a security control by itself. Segmentation requires an enforcement mechanism and explicit policy.

"Internal" should not automatically mean trusted. User devices, application servers, administrative hosts, and databases can have materially different trust relationships even when they share a corporate network.

Encryption should not be treated as authorization. Transport protection and access control solve different security problems.

A public service should not be accepted merely because it is encrypted. The business requirement for public reachability should still be documented.

A firewall rule should not be evaluated only by destination port. Source, destination, protocol, direction, business purpose, identity, and application dependency can all affect whether a rule is appropriate.

Legacy services should not be kept indefinitely merely because another system depends on them. Dependencies should be documented and migration or compensating-control decisions should be explicit.

## Performance Considerations

The examples prioritize readability and deterministic policy evaluation.

The Python and JavaScript implementations use straightforward collection operations suitable for educational inventories. The JavaScript implementation creates a `Map` for asset lookup rather than repeatedly scanning the complete asset list.

The C++ implementation uses `std::map` for stable indexed lookup. Individual segmentation checks still iterate over rule collections because the example is intended to expose policy mechanics rather than optimize for very large rule tables.

A production-scale review engine could index policies by:

    source zone
        -> destination zone
            -> protocol
                -> port

Such indexing can reduce repeated scans when thousands of zones and rules are evaluated.

Performance should still be balanced against auditability. A highly optimized policy engine that is difficult to inspect can create governance problems even when its computational complexity is excellent.

## Security Considerations

The implementations deliberately operate on supplied inventory and policy data rather than conducting live network activity.

Production systems should protect network inventory because it can reveal:

- hostnames
- IP addresses
- service ports
- network architecture
- administrative paths
- database locations
- security-zone boundaries

Generated reports should therefore be access-controlled and handled according to the sensitivity of the underlying infrastructure information.

Configuration validation is also a security control. Invalid port values, unknown zones, duplicate identities, and inconsistent protocol metadata can cause assessment engines to produce incorrect results. The implementations reject several such conditions instead of silently normalizing them.

The report writers use structured output rather than constructing executable commands from inventory values. This reduces the risk of turning untrusted configuration data into shell or command injection when the assessment system is extended.

## Production Considerations

A production network review system would normally connect the inventory model to authoritative sources such as approved configuration management systems, firewall policy repositories, cloud network controls, DNS records, asset inventories, and application ownership records.

The inventory should have lifecycle metadata so that temporary services and retired assets are not treated as permanent infrastructure.

Every public service should have an owner and documented purpose. Every cross-zone flow should have a business reason and an identified destination.

Policy changes should be reviewed for both connectivity impact and security impact. Removing an unnecessary public service can reduce exposure, while an overly broad new allow rule can undermine segmentation even when the rule is technically functional.

The most important distinction is between a diagram and an enforced control. A documented DMZ architecture does not provide protection if routing, firewall policy, security groups, host firewalls, or other enforcement mechanisms permit traffic that the diagram claims is prohibited.

## Practical Architecture

The three implementations converge on the same conceptual architecture without being line-by-line translations.

    Inventory
       |
       +--> Service exposure review
       |       |
       |       +--> Public endpoints
       |       +--> Authentication
       |       +--> Encryption
       |       +--> Protocol classification
       |
       +--> Segmentation policy review
               |
               +--> Source zone
               +--> Destination zone
               +--> Service
               +--> Port
               +--> Business justification
                       |
                       v
                 Security findings
                       |
                       v
                 Machine-readable report

This architecture keeps different security questions separate while allowing their results to be combined into a single review.

## Key Technical Distinctions

| Area | Primary question | Example from the implementations |
|---|---|---|
| Attack surface | What reachable functionality exists? | Count and classify Internet-facing services |
| Exposed service | Across which boundary can a service be reached? | HTTPS or SSH assigned `internetExposed=true` |
| Insecure protocol | Does the communication mechanism provide required protection? | FTP modeled as insecure and unencrypted |
| Segmentation | Which zones may communicate? | Application-to-database PostgreSQL flow |
| Administrative boundary | Who can reach privileged services? | User-to-management SSH rule |
| Asset criticality | What is the potential business impact? | Database and payment-style systems receive higher criticality |

Keeping these concepts distinct prevents a review from collapsing all network risks into a single "open port" category.

## Expected Demonstration Results

Running the Python program produces findings for the sample FTP exposure, unauthenticated public service characteristics, high-criticality placement, and segmentation relationships. It writes `network_security_review_report.json`.

Running the JavaScript program with Node.js produces event-driven review-stage messages, inventory metrics, findings, and `network-security-review.json`.

Compiling the C++ program with C++17 or later produces the enterprise governance review and writes `network_security_review_cpp.json`.

The sample environment intentionally contains policy weaknesses so that the assessment engines have meaningful conditions to detect. The findings are part of the demonstration model and should not be interpreted as an assessment of any real infrastructure.
