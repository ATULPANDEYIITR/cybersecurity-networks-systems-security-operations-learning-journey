# Windows Networking: SMB, RDP, WinRM, RPC, and Windows Firewall

## Scope

Windows networking combines application protocols, remote administration mechanisms, service discovery, and host-level traffic filtering. These components are related, but they solve different problems.

- **SMB (Server Message Block)** provides file sharing, printer sharing, and related Windows network operations.
- **RDP (Remote Desktop Protocol)** supports interactive remote desktop sessions.
- **WinRM (Windows Remote Management)** provides a management transport used by PowerShell remoting and other Windows administration tools.
- **RPC (Remote Procedure Call)** allows software components to request operations from other processes or machines. Windows RPC commonly uses an endpoint mapper to locate service endpoints.
- **Windows Firewall** filters network traffic according to configured rules, network profiles, addresses, ports, and other supported conditions.

A service's standard port is a useful diagnostic reference, not proof that the service is enabled or healthy. A successful TCP connection does not prove that authentication succeeds, the application protocol is correctly configured, or access is authorized.

## Standard endpoints

| Service | Common TCP port | Purpose | Important distinction |
|---|---:|---|---|
| SMB | 445 | File and printer sharing | Share permissions, filesystem permissions, and SMB security settings govern access. |
| RDP | 3389 | Interactive remote desktop | Network reachability is separate from user authentication and session authorization. |
| WinRM | 5985 | WinRM HTTP listener when configured | HTTP transport configuration must not be assumed to provide transport encryption. |
| WinRM | 5986 | WinRM HTTPS listener when configured | HTTPS requires a correctly configured listener and certificate. |
| RPC | 135 | RPC endpoint mapper | The endpoint mapper identifies RPC endpoints; dependent services may use additional ports. |

These are common configurations. Administrators can change service bindings, use gateways, or apply policies that restrict traffic to approved sources.

## SMB: file-sharing access and permissions

SMB carries operations for network shares and related services. A client can reach TCP 445 while still being unable to open a particular share because the server may reject authentication, share permissions, filesystem permissions, or the requested operation.

Security decisions should consider the complete access path:

- **Network reachability:** Can the client reach the SMB endpoint?
- **Authentication:** Does the server accept the identity and authentication method?
- **Share permissions:** Is the identity allowed to access the requested share?
- **Filesystem permissions:** Is the identity allowed to read, write, or execute the underlying files?
- **Protocol security:** Are supported SMB signing and encryption settings appropriate for the environment?

SMB 3.x supports security features that should be evaluated against organizational requirements. SMB signing helps protect message integrity. SMB encryption protects SMB traffic in supported configurations. These mechanisms address different risks and are not substitutes for least-privilege permissions.

SMB1 should not be enabled merely to resolve a connectivity problem. A failed connection should be investigated through name resolution, routing, firewall policy, service state, authentication, and protocol compatibility.

The Python implementation includes SMB's common TCP endpoint in its diagnostic reference. The SQL model records SMB requirements, sampled reachability, and reviewed firewall rules. Neither implementation assumes that an open port means a share is accessible.

## RDP: remote interactive sessions

RDP provides remote graphical sessions to Windows systems. Its common TCP endpoint is 3389, although actual connectivity can depend on configuration, gateways, network policy, and other transport settings.

RDP access should be controlled at several layers:

- Network rules should restrict access to approved management networks or gateways.
- Network Level Authentication should be required where supported and appropriate.
- User accounts should have only the remote-access rights they need.
- Administrative accounts should use strong authentication and appropriate monitoring.
- Internet-facing RDP should be avoided when a controlled gateway or VPN provides a safer access path.

A TCP connection to port 3389 only establishes that a connection was accepted. It does not prove that an RDP session can be negotiated or that a particular user can sign in.

The C++ case study models RDP as a declared dependency of an administrative workstation. A source-restricted rule represents the intended management path. The model reports a blocked required dependency separately from an allowed service that is not declared as required.

## WinRM: remote administration

WinRM is a Windows management transport used by PowerShell remoting and other management clients. Its commonly configured HTTP and HTTPS listeners use TCP ports 5985 and 5986, respectively.

WinRM should be treated as an administrative interface rather than an ordinary application endpoint. A permitted connection can enable powerful management operations if the caller has sufficient rights.

Relevant controls include:

- Restricting inbound management access to approved administrative systems.
- Selecting an appropriate authentication method for the environment.
- Configuring HTTPS listeners and certificates when HTTPS is required.
- Limiting administrative privileges and the accounts permitted to use remoting.
- Reviewing listener configuration, firewall rules, and remoting authorization together.

The HTTP port does not by itself establish whether a deployment is secure or insecure. Security depends on the actual listener, authentication, message-protection behavior, and configuration. HTTPS on 5986 is a common option, but the listener must be configured correctly.

The examples model WinRM HTTP and HTTPS as separate endpoints. A policy can permit 5986 from a management source while blocking 5985. That distinction avoids treating both ports as interchangeable.

## RPC: endpoint discovery and dependent services

Windows RPC allows components to invoke operations across process and machine boundaries. Many Windows management and infrastructure functions depend on RPC.

TCP 135 is commonly used by the RPC endpoint mapper. Clients can query the mapper to locate a service's endpoint. The actual RPC communication may then use a different port, including a dynamically allocated port depending on the service and configuration.

This creates an important diagnostic distinction:

- If TCP 135 is unreachable, endpoint discovery through that path may fail.
- If TCP 135 is reachable, the requested RPC service may still be unavailable.
- If the endpoint mapper returns an endpoint, firewall policy must also permit the required follow-up communication.
- A fixed-port check cannot discover every dynamic RPC dependency.

A firewall policy for RPC must be designed around documented service requirements, supported configuration, and the organization's security boundaries. Opening broad dynamic ranges without a dependency analysis can expose more services than necessary.

The Python, C++, Java, and SQL implementations explicitly identify port 135 as an endpoint-mapper reference rather than representing it as the complete RPC transport.

## Windows Firewall: profiles and traffic rules

Windows Firewall filters traffic using rules and active network profiles. The Domain, Private, and Public profiles allow different policy behavior according to network classification.

A rule can include conditions such as direction, action, profile, local and remote addresses, protocol, port, program, and service. Real effective behavior can also depend on Group Policy, local policy, rule-merging settings, and platform-specific precedence.

A useful review distinguishes three questions:

- **Is the application dependency required?** This is a business and system-design question.
- **Does the current policy permit the traffic?** This is a configuration question.
- **Does the endpoint actually respond?** This is an observation about the current system and network path.

These answers should not be collapsed into one status. A required service can be blocked, an unrequired service can be exposed, and a permitted service can still be unavailable because no listener is running.

The included firewall-policy examples are educational models. They use explicit matching rules and a default inbound decision to illustrate policy evaluation. They do not reproduce the full Windows Filtering Platform or claim to calculate effective policy on a real host.

## Python implementation

The Python script provides a read-only diagnostic workflow using the standard library.

### Service inventory

`WindowsService` stores each service's purpose, common TCP ports, transport, and security notes. The `SERVICES` dictionary makes the service reference explicit and allows input validation before any network connection is attempted.

### TCP connectivity checks

`validate_host()` rejects empty, malformed, and excessively long host inputs. `tcp_probe()` attempts a bounded TCP connection and returns the destination, port, result, elapsed time, and any socket error.

`inspect_service()` applies the service inventory to the selected service. WinRM is tested on both common ports because its HTTP and HTTPS listeners are separate endpoints.

The report is JSON so that diagnostic results can be stored or processed by other scripts. Connection errors remain visible rather than being reduced to an unexplained Boolean.

### Local inspection guidance

`build_firewall_guidance()` prints commands for inspecting firewall profiles, enabled rules, listening TCP sockets, SMB configuration, RDP configuration, WinRM listeners, and RPC endpoint mappings. The commands are presented for review rather than executed automatically.

`windows_only()` demonstrates bounded subprocess execution without shell interpolation. It is intended for explicitly selected local inspection commands on Windows.

The self-tests exercise hostname validation, unknown-service rejection, and invalid-port rejection. They do not require access to a real Windows server.

## JavaScript implementation

The Node.js implementation emphasizes asynchronous diagnostics and explicit policy evaluation.

`probeTcp()` wraps a TCP socket in a Promise. Connection, timeout, and error events all lead to one guarded completion path, so a socket cannot generate multiple results for the same probe.

`Promise.all()` runs the small set of endpoint checks concurrently. This reduces total wait time when individual connections have independent delays. Larger inventories should use a concurrency limit to avoid unnecessary load.

The `FirewallPolicy` class stores an inbound default action and a set of modeled rules. Its `evaluate()` method matches the service, port, profile, and optional source address. The `modelOnly` field makes the limitation explicit: this is a small policy evaluator, not a replacement for Windows Firewall's native evaluation.

The program accepts `--host`, `--services`, and `--timeout` arguments. The optional `--policy` mode exercises the policy model without requiring network access.

## C++ case study: asset and connectivity governance

The C++17 program models an enterprise environment with a file server and an administrative workstation.

### Architecture

- `Asset` describes a host and the services declared as required by its application or operational role.
- `FirewallRule` represents a service-specific rule, a port, a profile, an action, and an optional approved source.
- `NetworkGovernanceEngine` owns the inventory and rules, validates additions, evaluates modeled policy, and produces assessments.
- `Assessment` records the endpoint, dependency requirement, policy decision, and an explanation of the result.

The engine uses a map for hostname-based inventory lookup and a vector for ordered policy rules. Inventory lookup is efficient for an exact hostname, while rule evaluation scans the rule collection. For a large rule set, an index keyed by service, port, profile, and source could reduce repeated scans.

### Failure handling

The engine rejects duplicate asset names, empty hostnames, invalid ports, unnamed rules, and requests for unknown assets. These are configuration errors rather than connectivity outcomes, so the program reports them through exceptions.

The report distinguishes a blocked required dependency from an allowed service that the asset does not declare as required. This provides a practical basis for reviewing accidental exposure and application outages.

The model intentionally does not claim that an allowed rule proves a service is listening. It also does not implement the full Windows Firewall precedence model.

## Java implementation: typed enterprise governance

The Java 17 program uses explicit domain types to keep inventory, policy, and assessment data separate.

`NetworkService`, `FirewallProfile`, `RuleAction`, and `AssetState` are enums. These restrict values to defined states and make invalid combinations easier to detect.

The `NetworkAsset` record stores ownership, the expected profile, required services, and lifecycle state. Its compact constructor validates required fields and copies the supplied service set so that callers cannot mutate the asset's dependency collection through the original reference.

The `FirewallRule` record validates the port range and ensures that the port belongs to the selected service's standard endpoint set. This prevents a common configuration error, such as assigning TCP 445 to an RDP rule.

`FirewallPolicy` evaluates rules, while `NetworkGovernanceService` manages the asset inventory and creates immutable assessment results. A retired asset cannot receive an active assessment. Duplicate registrations and unknown hostnames are rejected explicitly.

This design separates policy decisions from inventory lifecycle management. In a production service, the same boundary would allow rule storage, audit logging, authorization, and change approval to be implemented independently.

## SQL data model

The PostgreSQL script represents the same operational domain relationally without attempting to duplicate a live Windows configuration database.

### Entities and relationships

| Table | Responsibility |
|---|---|
| `network_assets` | Host identity, owner, environment, firewall profile, and lifecycle state. |
| `windows_services` | SMB, RDP, WinRM, and RPC definitions with security guidance. |
| `service_endpoints` | Standard service-to-port mappings. |
| `service_requirements` | Approved service dependencies for each asset. |
| `network_observations` | Time-stamped, source-specific TCP connectivity results. |
| `firewall_rules` | Reviewed modeled rules, profiles, actions, optional sources, and change tickets. |

Foreign keys prevent requirements and observations from referring to missing inventory entries. Check constraints restrict lifecycle states, profiles, actions, observation results, and valid port ranges. Unique constraints prevent duplicate hostnames, duplicate service definitions, and duplicate endpoint mappings.

The `INET` and `CIDR` types provide PostgreSQL-native storage for observed source addresses and rule networks. These types are more suitable for network data than unrestricted text fields.

### Indexes and assessment queries

The observation index supports retrieval of recent results by asset. The partial firewall-rule index targets enabled rules, while the service-requirement index helps answer dependency-oriented queries.

The `windows_networking_assessment` view uses `DISTINCT ON` to select the latest observation for each asset and endpoint. It then joins the endpoint inventory with the declared service requirements.

The view supports two distinct operational questions: which required endpoints have failed their most recent check, and which unrequired endpoints were observed as reachable. Neither finding independently establishes a security vulnerability; both require interpretation in the context of the actual application and network policy.

The script uses a savepoint and a nested exception-handling block to demonstrate how a constraint violation can be detected without leaving an invalid endpoint record behind.

## Troubleshooting methodology

### SMB connection failures

Check hostname resolution, routing, TCP 445 reachability, service state, authentication, share permissions, filesystem permissions, and SMB security compatibility. A successful port check does not establish access to a share.

### RDP connection failures

Verify the target address, routing, TCP 3389 policy, Remote Desktop configuration, account rights, NLA requirements, and any gateway or VPN dependencies. Separate a network timeout from an authentication rejection.

### WinRM failures

Inspect configured listeners, certificates when HTTPS is used, authentication settings, remoting authorization, and the applicable firewall profile. Verify whether the client is expected to use TCP 5985 or 5986.

### RPC failures

Determine whether endpoint mapping is available and whether the requested RPC service's actual endpoint is reachable. A successful TCP 135 test alone does not validate the complete RPC operation.

### Firewall discrepancies

Compare the observed network profile, effective policy, enabled rules, remote address, and service bindings. Review domain policy and local rule-merging behavior before changing a rule. A local configuration inspection and a remote connectivity test provide different evidence and should be retained separately.

## Security and production limitations

The included tools intentionally avoid credential collection, remote command execution, firewall modification, and automated broad-range scanning. Their purpose is to support controlled diagnostics and policy review.

Before using similar checks operationally, obtain authorization for each target, keep timeouts bounded, limit concurrency, record timestamps and test sources, and avoid exposing sensitive host information in logs.

A production monitoring system should also distinguish an unreachable endpoint from a timeout, a rejected connection, a DNS failure, and an untested endpoint. Results need freshness limits because an observation from an earlier time may not reflect the current network state.

Finally, a secure deployment requires more than closing or opening standard ports. Service configuration, authentication, authorization, encryption, source restrictions, network segmentation, patching, logging, and change governance must work together.
