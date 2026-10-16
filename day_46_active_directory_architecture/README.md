# Active Directory Architecture: Forests, Trees, Domains, Trusts, LDAP, and DNS

## Architectural scope

Active Directory Domain Services (AD DS) provides a distributed directory for managing identities, computers, groups, domain controllers, and directory configuration. Its architecture combines a logical hierarchy, authentication and trust relationships, a directory access protocol, and a name-resolution system.

These mechanisms have different responsibilities:

- **Forests and trees** describe the logical directory namespace and organizational boundaries.
- **Domains** organize directory objects, domain controllers, policies, and replication within a directory namespace.
- **Trusts** establish relationships that can permit authentication across security boundaries. A trust does not automatically authorize every resource request.
- **LDAP** provides operations for reading and modifying directory entries.
- **DNS** allows clients and services to locate domain controllers and other directory-related services.

The implementations in this repository model these relationships using executable examples, domain-specific data structures, validation, service discovery, and relational queries. They are educational simulations rather than substitutes for Windows domain controllers or real authentication protocols.

## Forests, trees, and domains

### Forest

A forest is the principal logical and security boundary in an AD DS deployment. It contains one or more domains and shares a schema, configuration partition, and global catalog infrastructure. Forest-wide administration and schema changes affect the forest rather than a single isolated domain.

The forest root domain establishes the root of the forest namespace. It is not merely a label for a collection of unrelated domains.

The Python and Java implementations associate each domain with a forest root. Their validation prevents a domain from being inserted into a forest when its declared forest membership does not match the forest being configured.

### Tree

A tree is a set of domains whose DNS namespaces form a contiguous hierarchy. A root domain such as `corp.example.com` can have child domains such as `engineering.corp.example.com` and `research.corp.example.com`.

These domains form one tree because the child names extend the parent's DNS namespace. A separate tree in the same forest has a different namespace root. Trees within one forest still share forest-level directory structures and automatically established trust relationships.

The programs validate child-domain names against their declared parent. The Python and Java examples also require a parent domain to exist before adding a child.

This validation illustrates an important distinction: DNS suffix matching alone is not enough to establish legitimate forest membership. A production deployment must also verify directory configuration, domain ownership, controller health, and the appropriate trust and replication state.

### Domain

A domain is an administrative and replication unit containing directory objects and domain controllers. Domain objects include users, groups, computers, and organizational units.

The domain DNS name is distinct from an object's distinguished name. For example:

- Domain DNS name: `engineering.corp.example.com`
- LDAP search base: `DC=engineering,DC=corp,DC=example,DC=com`
- User distinguished name: `CN=Riya Sharma,OU=Engineering,DC=engineering,DC=corp,DC=example,DC=com`

The DNS name locates the domain namespace. The distinguished name identifies an entry within the directory tree.

A domain is not equivalent to an organizational unit. Organizational units organize objects inside a domain and can provide a scope for delegated administration and Group Policy. They do not create separate domains or forests.

## Trust relationships

Trusts describe how authentication relationships can cross directory boundaries. They are not a substitute for authorization, resource permissions, or security policy.

### Direction

Trust direction is defined relative to the trusting relationship and its source and target. Operationally, the direction determines which side can rely on the other side's authentication assertions.

The simulations use directed edges to represent the permitted direction of trust reachability:

| Configuration | Modeled relationship |
|---|---|
| Outbound | The source forest trusts the target forest |
| Inbound | The target forest trusts the source forest |
| Bidirectional | Both directions are represented |
| Disabled | The relationship is excluded from reachability evaluation |

The Python and JavaScript implementations make direction explicit. The C++ and Java programs represent it with enums, preventing arbitrary strings from being silently interpreted as valid directions.

### Scope and transitivity

A domain trust, forest trust, and external trust differ in scope and behavior. A forest trust can support authentication across forests, subject to its configuration and applicable policies. External trusts are generally used for specific relationships outside the forest-trust model.

A transitive trust may participate in a chain of trust relationships. A non-transitive trust is restricted to its direct relationship and must not be treated as a path to unrelated domains.

The trust graph implementations illustrate reachability as a graph traversal problem. This is useful for reasoning about direction and connectivity, but real AD DS trust evaluation includes protocol behavior, trust attributes, selective authentication, SID filtering, name-suffix routing, Kerberos configuration, and other conditions not represented by a simple graph.

**Trust reachability is not proof of successful authentication.** It also does not establish that a user has permission to access a file share, application, database, or other protected resource.

## LDAP and directory naming

LDAP, the Lightweight Directory Access Protocol, provides a protocol for accessing directory entries. Clients typically connect to an LDAP service hosted by a domain controller, bind using an appropriate identity or authentication mechanism, and issue searches using a base distinguished name, scope, filter, and requested attributes.

### Distinguished names and search bases

An LDAP distinguished name describes an entry's position in the directory hierarchy. Relative distinguished names identify entries at individual levels, while the complete distinguished name identifies the entry in its naming context.

The Python implementation constructs a domain search base from the domain's DNS labels. The JavaScript implementation normalizes attribute names and stores directory objects in a map keyed by distinguished name. The Java implementation uses a `DistinguishedName` record to validate entry identifiers.

These structures demonstrate useful modeling rules:

- Distinguished names should be unique within the modeled domain.
- LDAP attribute names should be handled consistently, including case-insensitive lookup where appropriate.
- A search should operate within a defined domain or naming context.
- The caller's permissions determine which entries and attributes are accessible in a real directory.

### Search filters and input safety

An LDAP search filter identifies entries matching specified conditions. A filter such as `(objectClass=user)` selects user entries, while a filter combining object class and department can narrow the result set.

Untrusted values must be escaped according to LDAP filter rules before being inserted into a filter assertion. Characters such as `*`, `(`, `)`, backslash, and the null character have special meaning in LDAP filters.

The Python and JavaScript programs include escaping functions to demonstrate this protection. Escaping assertion values is not the same as escaping an entire LDAP filter or a distinguished name. Applications must use the encoding appropriate to the specific LDAP context and must not treat an escaped input as an authorization decision.

### LDAP availability and authentication

Discovering an LDAP endpoint does not guarantee that an LDAP operation will succeed. Network connectivity, TLS configuration, server availability, bind credentials, account restrictions, and directory permissions can all affect the result.

The JavaScript program emits separate events for successful service discovery, completed searches, and discovery failures. The SQL implementation stores search outcomes and service observations separately so operators can distinguish a successful lookup from a later bind or query failure.

## DNS dependency and service discovery

AD DS relies on DNS to locate domain controllers and directory services. A client generally needs to discover a suitable domain controller before performing many domain operations.

SRV records describe a service, transport protocol, priority, weight, port, and target host. Common directory-related records include:

| Record name pattern | Purpose |
|---|---|
| `_ldap._tcp.<domain>` | Locates LDAP services over TCP |
| `_kerberos._tcp.<domain>` | Locates Kerberos services over TCP |
| `_kerberos._udp.<domain>` | Locates Kerberos services over UDP where configured |
| `_ldap._tcp.dc._msdcs.<domain>` | Supports domain-controller discovery |
| `_ldap._tcp.pdc._msdcs.<domain>` | Locates the PDC emulator role holder in applicable discovery scenarios |

These names are examples of AD-related DNS conventions, not a complete inventory of the records required by every deployment.

The Python, JavaScript, C++, and Java models store LDAP SRV records and select candidate endpoints using priority and weight. Lower numeric SRV priority is preferred; weight is used to distribute selection among records of equal priority. A production resolver must also account for DNS caching, record TTLs, unavailable targets, network reachability, and client-specific domain-controller selection.

DNS and LDAP are separate operational layers. A valid SRV record can point to an unavailable server. A reachable server can reject an LDAP bind. An LDAP query can succeed while an unrelated Kerberos operation fails.

For troubleshooting, check the service record, resolve the target host, verify network access to the relevant port, and test the actual protocol operation. Do not assume that a successful DNS query proves the entire directory service is healthy.

## Python implementation

The Python script models the directory environment using dataclasses and dictionaries.

`Forest` validates the root domain and child-domain membership. `Domain` maintains directory entries indexed by case-insensitive distinguished name and supports searches by object class and attribute value. `DirectoryEnvironment` registers forests, DNS records, and trusts.

`DnsRecord` validates supported record types and checks that A and AAAA records contain addresses of the correct IP version. SRV records require a valid port and an absolute target name. The DNS catalog prevents duplicate name/type combinations in the simplified model.

The trust evaluation method builds directed forest-trust edges and performs breadth-first traversal. Same-forest domains are treated as sharing the forest's implicit trust relationship. The method deliberately models reachability rather than real credential validation.

The demonstration includes:

- A corporate forest with engineering and research child domains.
- User, computer, and group objects with realistic distinguished names.
- LDAP and Kerberos service records.
- A separate partner forest connected through a bidirectional forest trust.
- Search operations, DNS discovery, trust evaluation, LDAP filter escaping, and validation failures.

The script uses only the Python standard library. Its data structures are appropriate for a small in-memory model, but a large directory inventory would require more efficient indexing, persistent storage, and carefully scoped searches.

## JavaScript implementation

The JavaScript file uses Node.js's `EventEmitter` to model an event-driven directory service.

`DirectoryController` separates domain lookup, LDAP service discovery, search execution, and cross-forest reachability. Its events expose operational outcomes without coupling monitoring logic directly to the search implementation.

`DnsCatalog` retains multiple SRV records for a service name and orders candidates by priority and weight. `Domain` uses a map for efficient distinguished-name lookup and normalizes LDAP attribute names to lowercase. `TrustGraph` stores directed trust edges and evaluates reachability through a queue.

The program also demonstrates asynchronous application structure through a `main` function and uses assertions to verify expected behavior. Although the demonstration operations are in-memory, the structure is suitable for understanding how a real application can separate domain logic from asynchronous network calls.

The LDAP filter escaping function protects a filter assertion from structural injection. In a production Node.js service, connection pooling, TLS verification, timeouts, cancellation, bounded retries, and reliable error classification would also be necessary.

## C++ case study

The C++ program models an enterprise directory as a set of strongly typed components:

- `Domain` stores directory entries and constructs LDAP search bases.
- `Forest` checks the root-domain and child-domain hierarchy.
- `TrustGraph` represents directional trust relationships.
- `DnsCatalog` stores SRV records and orders service candidates.
- `DirectoryService` coordinates domain lookup, DNS discovery, and cross-forest reachability.

The implementation uses standard-library maps, vectors, queues, and sets. These structures make the relationships explicit and keep the model independent of third-party directory libraries.

The case study demonstrates how an enterprise service could separate configuration validation from runtime lookup. A malformed child domain should be rejected before it becomes part of the directory model. A missing LDAP SRV record should be reported as a discovery failure rather than as an empty successful search.

The program is intended as a compact architectural case study rather than a production directory client. Real service discovery requires DNS resolution, and actual directory searches require a protocol client, network error handling, appropriate credentials, and server-side authorization. The modeled trust graph must not be used as a substitute for AD DS authentication or access-control decisions.

## Java implementation

The Java program uses records, enums, immutable collections, and domain-specific classes to express directory configuration and service behavior.

`DistinguishedName`, `DirectoryEntry`, `SrvRecord`, and `Trust` represent validated values. Enums constrain object types, trust direction, trust scope, and service state. `Forest` enforces root and child-domain relationships, while `DirectoryService` coordinates searches and service discovery.

The trust service uses directed graph traversal to distinguish reachable forests from unrelated forests. Directory lookup, same-forest checks, and cross-forest checks remain separate operations so that a successful domain lookup is not mistaken for successful resource authorization.

The Java model also makes failure states explicit through `DirectoryException`. Missing domains and missing LDAP SRV records produce errors instead of silently returning an empty result.

For enterprise applications, these domain types provide a foundation for clearer boundaries between configuration management, directory access, health monitoring, and security policy. A production implementation would need to integrate with actual LDAP and Kerberos libraries and would need stronger handling of concurrent updates, credentials, and network failures.

## SQL relational model

The PostgreSQL script represents the directory architecture through related tables.

| Table | Responsibility |
|---|---|
| `forests` | Stores forest roots and modeled functional levels |
| `domains` | Represents forest membership, parent domains, and domain identifiers |
| `trusts` | Records trust scope, direction, transitivity, and enabled state |
| `directory_objects` | Stores users, groups, computers, organizational units, and other modeled objects |
| `dns_records` | Stores service-discovery and name records |
| `ldap_search_audit` | Records search outcomes, base names, identities, and failure reasons |
| `service_observations` | Tracks DNS, LDAP, Kerberos, and controller-related health observations |

Primary keys and foreign keys maintain entity relationships. Check constraints restrict trust directions, object classes, record types, ports, and other values. A partial unique index prevents multiple forest-root domain rows for the same forest, and indexes support domain lookup, directory searches, service discovery, and recent operational observations.

The `enforce_domain_hierarchy` trigger verifies that a root domain matches the forest root and that a child domain references a parent in the same forest with the expected DNS suffix. This is stronger than relying exclusively on application validation, although the simplified trigger does not validate every possible ancestry or DNS ownership rule.

`v_directory_objects` joins directory entries to their domain and forest context. `v_domain_controller_discovery` exposes enabled LDAP SRV records. `v_enabled_forest_trusts` presents active trust relationships without conflating them with resource authorization.

The recursive trust query evaluates directed forest-trust edges from a selected source. The result represents modeled reachability, not a complete AD DS trust evaluation. The audit tables distinguish directory query outcomes from the DNS and service health conditions that may have affected them.

The transaction demonstrates recording a search after confirming the target domain exists. A nested exception block tests invalid hierarchy handling without requiring the entire script to fail.

## Architecture and operational distinctions

The most important diagnostic distinction is between configuration, discovery, authentication, and authorization.

| Layer | Question answered | Example failure |
|---|---|---|
| Namespace | Which forest and domain contain the directory entry? | Incorrect domain hierarchy |
| DNS discovery | Where can the client find a domain controller? | Missing or incorrect SRV record |
| Network transport | Can the client reach the discovered endpoint? | Firewall or routing failure |
| Authentication | Can the client establish the required identity? | Kerberos or LDAP bind failure |
| Directory operation | Can the identity read or modify the requested entry? | Directory permissions deny the operation |
| Resource authorization | Can the authenticated identity access the protected resource? | Share or application ACL denies access |

These layers depend on one another but are not interchangeable. A healthy DNS service does not prove that a controller is reachable. A successful LDAP bind does not prove that the identity can read every object. A trust relationship does not automatically grant permission to use a resource.

## Security and implementation limitations

The simulations deliberately omit several features that are essential in production AD DS.

- **Real authentication:** Trust reachability is modeled as graph connectivity. It does not validate Kerberos tickets, passwords, service principal names, ticket lifetimes, or authentication policies.
- **Authorization:** The models do not implement access tokens, security descriptors, discretionary access-control lists, or resource-level permission checks.
- **Replication:** Domain controllers maintain replicated directory data. Replication topology, replication latency, lingering objects, and replication failures are outside the in-memory models.
- **LDAP transport security:** A production client should use correctly configured TLS or other approved secure LDAP mechanisms and validate the server identity.
- **DNS completeness:** The sample SRV catalog is illustrative. A real domain relies on the appropriate set of DNS zones, service records, registrations, delegation, and resolution paths.
- **Trust security:** Trust direction and transitivity alone do not capture selective authentication, SID filtering, trust attributes, or all forest-trust restrictions.
- **Directory query safety:** Filter escaping must be appropriate to the LDAP filter grammar. Distinguished names and LDAP filters use different escaping rules.
- **Operational resilience:** Production services need timeouts, bounded retries, monitoring, failover, credential protection, and clear separation of transient failures from invalid configuration.

A useful architecture assessment therefore examines the hierarchy, service-discovery records, trust direction, actual authentication path, and resource permissions separately. This produces more reliable diagnoses than treating forests, trusts, LDAP, and DNS as a single mechanism.
