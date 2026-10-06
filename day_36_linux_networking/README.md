# Linux Networking: Interfaces, Routes, Sockets, DNS, and Firewalls

## Scope

This repository is a technical study of Linux networking through five closely related mechanisms:

- network interfaces and addresses
- kernel routing
- transport-layer sockets
- DNS configuration and name resolution
- firewall configuration and packet policy

The implementations deliberately keep these mechanisms distinct. An interface provides a host attachment point and addresses. A route determines how the kernel can reach a destination. A socket represents an application or transport endpoint. DNS translates names into addresses through the configured resolver path. A firewall applies packet policy to traffic that reaches the relevant packet-processing hooks.

The examples use realistic Linux host behavior rather than treating networking as a collection of unrelated command examples.

## Networking model

A useful diagnostic chain is:

`application -> socket -> DNS/address selection -> route lookup -> interface -> packet filtering -> network`

The stages interact, but they solve different problems.

A DNS failure can prevent an application from learning an address even when the routing table is correct. A valid route can still lead to a connection failure because no process is listening on the destination port. A listening socket can still be unreachable because a firewall drops the packet. An interface can be operational while having an incorrect address or no usable route.

This separation is essential when diagnosing Linux connectivity.

## Network interfaces and addresses

A Linux network interface is the kernel's representation of a network attachment point. Common examples include physical Ethernet devices, wireless devices, virtual Ethernet pairs, bridges, VLAN interfaces, tunnels, and loopback.

The Python implementation uses `ip -j address` so interface information can be processed as structured JSON rather than relying on fragile parsing of human-oriented terminal output. It records interface names, flags, MTUs, and addresses.

The Java implementation uses `NetworkInterface`, which exposes interface state, MTU information, and assigned addresses through the Java standard library. This is useful for application-level diagnostics because it avoids parsing command output.

The C++ implementation reads `/proc/net/dev` for a lightweight kernel-visible interface inventory. It also explains why production-grade Linux tooling commonly uses netlink or `ip` when detailed interface attributes are required.

The SQL implementation separates `interfaces` from `interface_addresses`. That distinction is important because one interface can have multiple addresses, including addresses from different networks.

An address and an interface are therefore not interchangeable concepts. A route may select an interface, while the interface determines the layer-3 source address candidates and link-level path available to the kernel.

## Routing

Routing answers a specific question:

> Given a destination address, where should the packet be sent?

The examples use CIDR networks and longest-prefix matching.

For example, consider:

- `0.0.0.0/0` via `eth0`
- `10.0.0.0/8` via `eth1`
- `10.20.0.0/16` via `eth2`
- `10.20.30.0/24` via `eth3`

A destination of `10.20.30.44` matches all four networks, but `/24` is the most specific matching prefix. A destination of `10.20.8.9` matches the `/8` and `/16` entries, so the `/16` route is preferred.

The Python `select_route()` function implements this behavior in a deterministic model. The Java `RouteEngine` represents the same rule with immutable records and collection operations. The C++ case study explicitly compares prefix lengths and metrics.

Real Linux routing can be more sophisticated than these teaching models. Policy routing can involve routing rules, multiple routing tables, packet marks, network namespaces, VRFs, and other kernel mechanisms. Therefore, the model demonstrates the central longest-prefix concept without claiming to reproduce every kernel routing decision.

The Python diagnostic path also reads IPv4 and IPv6 routes through `ip -j route` and `ip -j -6 route`.

## Routes versus interfaces

An interface does not automatically mean that every destination reachable through that interface is reachable.

A route contains a destination prefix and normally identifies either:

- a directly connected interface, or
- a next-hop gateway reachable through an interface.

The database model captures this relationship through `routes.interface_id`.

A route can therefore be invalid operationally even if its record exists. For example, an interface may be administratively down, physically disconnected, incorrectly addressed, or unable to reach the configured gateway.

This is why interface inspection and route inspection should be performed together.

## Sockets

A socket represents an endpoint used by an application to communicate over a transport protocol.

The examples distinguish sockets from routes.

A listening TCP socket such as:

`0.0.0.0:443`

means that a process has requested a listening endpoint on TCP port 443 across the host's IPv4 addresses. It does not itself prove that remote clients can reach the service.

The Python implementation uses Linux `ss` to inspect TCP and UDP sockets. The JavaScript implementation does the same through Node's child-process API while also demonstrating Node's event-driven TCP client API.

The C++ implementation demonstrates a real POSIX TCP socket with:

- `socket()`
- `setsockopt()`
- `connect()`
- `close()`

The Java implementation uses `Socket` and `InetSocketAddress` to perform a TCP connectivity test with an explicit timeout.

A successful TCP connection demonstrates that the TCP handshake completed at that moment. It does not prove that an HTTP request, TLS negotiation, authentication process, or application-level transaction will succeed.

## DNS configuration

DNS solves a different problem from routing.

A hostname such as `api.example.com` must be translated into one or more addresses before an application can normally establish a connection to the service.

The Python implementation reads `/etc/resolv.conf` and extracts `nameserver`, `search`, and `domain` directives. It then uses Python's system resolver through `socket.getaddrinfo()`.

The JavaScript implementation reads the same configuration file and uses Node's `dns.lookup()`.

The Java implementation reads configured nameservers and performs resolution with `InetAddress.getAllByName()`.

`/etc/resolv.conf` should not automatically be interpreted as the permanent source of configuration. On many Linux systems it can be generated or managed by components such as systemd-resolved or NetworkManager.

This distinction matters when troubleshooting. Editing a generated file manually may not be a durable configuration change.

A DNS failure can therefore occur even when:

- the interface is up,
- the host has an address,
- the routing table has a default route,
- and the remote application is healthy.

The resolver path itself must be tested.

## DNS resolution and connectivity are different tests

Resolving a hostname tests name resolution.

Connecting to a resolved address tests transport reachability.

For example, a diagnostic workflow may establish:

`api.example.com -> 203.0.113.20`

and then test:

`203.0.113.20:443`

These are separate failure points.

If DNS succeeds but TCP fails, investigating resolver configuration further may not be useful until routing, firewall policy, service state, and remote reachability are examined.

If DNS fails, a TCP test against the hostname cannot reliably diagnose the underlying service because the application may never obtain a destination address.

## Firewall configuration

A firewall controls packet handling according to policy.

The examples use a first-match policy model to make rule ordering visible:

- TCP from `10.20.0.0/16` to port 22 is accepted.
- TCP traffic to port 443 is accepted.
- Unmatched traffic reaches a default `DROP` policy.

The model is intentionally smaller than a real nftables configuration.

Modern Linux systems commonly use nftables as the underlying packet-filtering framework. UFW may provide a higher-level management interface, while iptables commands may still exist through compatibility layers depending on the distribution.

The Python, JavaScript, and C++ programs inspect available firewall tooling but do not modify rules.

This is an intentional operational safety decision. A diagnostic script should not silently flush or replace a firewall because an incorrect rule can immediately remove remote administration access.

## Firewall rule ordering

Rule order matters in policies where the first matching rule determines the action.

Suppose a firewall has:

`accept TCP port 443`

followed by:

`drop TCP`

HTTPS traffic matches the first rule and is accepted.

If the order is reversed, the broad drop rule may consume the packet before the HTTPS exception is reached.

Real nftables policies can use richer structures than this simple first-match model, including chains, sets, stateful connection tracking, hooks, priorities, NAT, interfaces, address families, and connection states.

The SQL representation preserves rule order with `rule_order`.

## Firewall policy versus socket state

A firewall rule and a socket solve different problems.

A socket can be listening while a firewall prevents remote clients from reaching it.

Conversely, a firewall can allow traffic to a port where no process is listening. In that situation, the network path may reach the host, but the transport endpoint is unavailable.

A useful troubleshooting sequence is therefore:

`DNS -> route -> interface -> firewall -> socket -> application`

The exact order can change depending on the observed failure, but keeping the mechanisms separate prevents incorrect conclusions.

## Python implementation

The Python script is the broadest diagnostic implementation.

It provides read-only inspection of:

- interfaces through `ip -j address`
- IPv4 routes through `ip -j route`
- IPv6 routes through `ip -j -6 route`
- TCP and UDP sockets through `ss`
- DNS configuration through `/etc/resolv.conf`
- firewall state through nftables, UFW, or iptables where available

It also contains deterministic models for route selection and firewall decisions.

The route model uses `ipaddress` objects so prefix matching is based on actual network membership rather than string comparisons.

The firewall model represents packets and rules as dataclasses. A rule can constrain protocol, source network, destination network, and destination port.

The script also provides TCP connectivity testing through `socket.create_connection()` and hostname resolution through `socket.getaddrinfo()`.

The command execution layer uses argument arrays rather than `shell=True`. This avoids unnecessary shell parsing and reduces command-injection exposure when command parameters eventually originate from external input.

The script intentionally limits displayed firewall and socket output so a large production host does not flood the terminal.

## JavaScript implementation

The JavaScript implementation uses Node.js capabilities that fit network diagnostics naturally.

`os.networkInterfaces()` provides interface information without parsing the output of a Linux command.

Linux-specific route and firewall inspection is performed through Node's asynchronous child-process interface. The commands remain read-only.

The TCP test uses `net.createConnection()`, which demonstrates Node's event-driven socket model. Connection, timeout, and error events are handled separately.

The route model implements IPv4 CIDR matching with integer arithmetic. This demonstrates why prefix length matters while keeping the calculation explicit.

The JavaScript firewall model uses classes for rules and policies. This is different from the Python dataclass representation and emphasizes object behavior and event-driven network operations.

The implementation uses no npm dependencies.

## C++ case study

The C++ program represents a Linux application host with management, application, and default routes.

Its route engine demonstrates longest-prefix matching and uses the route metric as a simplified tie-breaker.

Its firewall model evaluates realistic packets such as:

`10.20.5.10:51000 -> 192.0.2.20:22`

and distinguishes management SSH from an unauthorized external SSH attempt.

The C++ implementation also demonstrates the relationship between low-level Linux facilities and application behavior.

`/proc/net/dev` exposes interface statistics and names, while `/proc/net/route` exposes kernel IPv4 route information. The program explains why `ip` and netlink are generally more convenient for detailed operational tooling.

The TCP test uses POSIX sockets directly. The program creates an `AF_INET`/`SOCK_STREAM` endpoint, configures a timeout, constructs a `sockaddr_in`, calls `connect()`, measures elapsed time, and closes the descriptor.

This makes the transport endpoint lifecycle visible rather than hiding it behind a high-level client library.

## Java implementation

The Java implementation models networking as an enterprise diagnostic service.

`NetworkInventoryService` uses Java's `NetworkInterface` abstraction to inspect interfaces and addresses.

`Route` and `RouteEngine` model route selection using immutable records and collection processing. The route engine explicitly orders candidates by prefix specificity and then metric.

`FirewallRule`, `FirewallPolicy`, `Packet`, and `FirewallDecision` separate policy definition from policy evaluation. This makes a firewall decision a domain result rather than merely a printed conditional.

`DnsService` separates resolver configuration inspection from hostname resolution.

`TcpConnectivityService` owns the transport-level connection test and applies an explicit timeout so an unreachable endpoint does not cause an indefinitely blocked diagnostic operation.

The domain types make invalid states easier to detect and keep policy decisions explicit.

## SQL data model

The PostgreSQL schema represents the same Linux networking domain relationally.

`hosts` represents Linux machines.

`interfaces` represents network interfaces attached to those hosts.

`interface_addresses` represents addresses assigned to interfaces. Its foreign key makes the one-host-to-many-interface-to-many-address relationship explicit.

`routes` stores destination CIDRs, gateways, metrics, protocol origins, and interface relationships.

`sockets` records protocol, state, local endpoint, peer endpoint, and process information.

`dns_configurations` and `dns_nameservers` separate resolver configuration sources from individual resolver addresses.

`firewall_chains` represents policy containers, while `firewall_rules` stores ordered packet-matching rules.

`firewall_decisions` provides an audit-oriented representation of evaluated traffic.

PostgreSQL's `inet` and `cidr` types are particularly appropriate here. They allow network operations such as containment and prefix-length inspection without storing IP addresses as arbitrary text.

## Database integrity

The SQL schema uses constraints for rules that belong at the relational layer.

Port ranges are constrained to `1` through `65535`.

Protocol values are restricted to known values.

Interface names are unique within a host.

Firewall rule ordering is unique within a chain.

Foreign keys prevent routes, sockets, DNS records, and firewall policies from referencing nonexistent parent entities.

Indexes support common operational queries such as:

- looking up addresses by network
- finding routes for a host
- finding sockets by protocol and state
- retrieving firewall rules in rule order
- retrieving recent firewall decisions

The database therefore does more than store arbitrary configuration text. It expresses relationships and validation rules structurally.

## Longest-prefix lookup in PostgreSQL

PostgreSQL's network types allow a route query such as:

`'10.20.55.10'::inet <<= destination`

to identify routes containing a destination address.

Ordering candidate routes by:

`masklen(destination) DESC`

implements the central longest-prefix principle used in the teaching model.

A lower metric can then be used as a simplified tie-breaker.

This query should not be interpreted as a complete replacement for Linux policy routing because Linux can select among routing rules and tables before the final route is chosen.

## Transactional network configuration

The SQL script includes a transaction that adds a route and immediately queries the staged state before committing.

The transaction demonstrates an important database property: related configuration changes can be committed atomically.

A production network controller would need stronger coordination with the actual Linux kernel state. Database state alone does not make a kernel route exist.

The SQL model is therefore a representation and policy layer, not a substitute for applying configuration through netlink, `ip`, NetworkManager, systemd-networkd, or another appropriate control mechanism.

## Edge cases

### Interface problems

An interface can be administratively down, physically down, missing an address, or assigned an unexpected network.

An operational check should distinguish these states rather than reporting only that an interface object exists.

### Routing problems

A default route can exist while a more specific route sends traffic toward an incorrect gateway.

A route can also reference an interface that is down.

IPv4 and IPv6 must be considered separately. An IPv6 route problem cannot necessarily be diagnosed from an IPv4 routing table.

### Socket problems

A port can be unused, a process can listen only on loopback, or a service can listen on one address but not another.

A connection timeout and an immediate connection refusal can therefore carry different diagnostic information.

### DNS problems

`/etc/resolv.conf` may be generated rather than manually managed.

A resolver can be configured but unreachable.

A hostname can resolve to multiple addresses, and applications may choose among them differently depending on address family and connection strategy.

### Firewall problems

A broad rule placed before a narrow exception can block traffic unexpectedly.

A default drop policy makes missing allow rules visible but can also block legitimate management access.

Firewall state and application state must be investigated separately.

## Common diagnostic mistakes

Treating `ping` as a universal connectivity test is misleading. ICMP behavior can differ from TCP or UDP behavior, and an application can be reachable even when ICMP is filtered.

Treating DNS resolution as proof of service availability is also incorrect. Name resolution ends before the transport connection begins.

Treating an open TCP port as proof that an application is healthy is equally unsafe. The process can accept connections while returning application errors.

Editing `/etc/resolv.conf` without checking which component manages it can produce a temporary change that is overwritten.

Changing firewall rules remotely without preserving an administrative access path can disconnect the operator.

Using a route from one network namespace to reason about another namespace is incorrect. Linux network namespaces can have separate interfaces, routes, sockets, and firewall state.

## Security considerations

Network diagnostics should follow least privilege.

Read-only inspection should not automatically run with elevated privileges.

Firewall modification should be explicit, auditable, and reversible.

Command execution should avoid shell interpolation when arguments can be passed directly to an executable.

Hostnames, IP addresses, ports, and CIDR values should be validated before they are used by diagnostic logic.

Firewall policies should use a clear default posture and narrowly scoped exceptions.

Management ports such as SSH should generally be restricted to appropriate administrative networks rather than exposed indiscriminately.

Listening services should be periodically inventoried because an unexpected listener can indicate a configuration error or compromise.

## Performance considerations

Route lookup normally benefits from efficient prefix structures because a production router may evaluate large numbers of prefixes.

The teaching implementations use linear scans because the algorithm is easier to inspect. Their route lookup complexity is approximately `O(n)` for `n` candidate routes.

A production implementation handling large routing tables may use kernel routing facilities, prefix trees, or specialized networking libraries rather than repeatedly scanning every route in application code.

Socket inspection can also produce large datasets on busy hosts. The Python and JavaScript examples deliberately limit displayed records.

Database indexes on network columns and operational lookup fields become increasingly important as inventories grow.

## Production boundaries

The programs are intentionally diagnostic and educational rather than host configuration managers.

They do not silently:

- flush firewall rules
- replace nftables policies
- change routes
- modify interface addresses
- rewrite DNS configuration
- restart networking services

Actual configuration management should account for rollback, remote-access safety, persistence across reboot, ownership by the system's network manager, and coordination with infrastructure policy.

The key engineering distinction is between observing network state, modeling network decisions, and changing network state. These implementations primarily perform the first two operations.
