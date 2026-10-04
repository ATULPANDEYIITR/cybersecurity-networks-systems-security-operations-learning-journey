# Linux Services: systemd, Daemons, Service Configuration, and Startup Services

## Scope

This learning artifact models Linux service management around four closely related but distinct areas:

- **systemd** is the service manager and init system responsible for loading units, resolving dependencies, activating services, supervising processes, handling failures, and coordinating boot targets.
- **Daemons** are long-running background processes that provide capabilities such as APIs, metrics collection, scheduled processing, logging, or network services.
- **Service configuration** describes how a daemon is executed and supervised. A systemd service unit commonly contains execution, identity, environment, working-directory, dependency, restart, and installation information.
- **Startup services** are services associated with a boot target through enablement. Being enabled for startup is not the same as being active at every moment, and a static unit can be activated because another unit depends on it without being independently enabled.

The implementations use an operations scenario involving network readiness, a metrics daemon, an orders API, and a billing worker. The examples deliberately separate configuration errors, dependency failures, runtime failures, restart policy, and startup participation.

## Core systemd model

systemd treats configuration as units. A service unit normally has a name ending in `.service` and is described using sections such as `[Unit]`, `[Service]`, and `[Install]`.

A representative unit in the implementations has the conceptual form:

    [Unit]
    Description=Orders API daemon
    After=network-online.target.service metrics-agent.service

    [Service]
    Type=simple
    ExecStart=/opt/orders/bin/server --port 8080
    User=orders
    Restart=on-failure
    RestartSec=5

    [Install]
    WantedBy=multi-user.target

The `[Unit]` section describes relationships and ordering. `After=` establishes ordering relative to other units. It does not by itself mean that the referenced service is automatically started.

The `[Service]` section describes process execution and supervision. `ExecStart=` identifies the process to launch. `User=` reduces the privileges under which the service runs. `Restart=` describes automatic recovery behavior, while `RestartSec=` controls the delay before a restart attempt.

The `[Install]` section describes how the service participates in target-based startup when it is enabled. `WantedBy=multi-user.target` associates the service with a normal multi-user boot target.

A unit file is configuration consumed by systemd. It is not simply a shell script. Treating it as declarative service configuration makes dependency handling, supervision, status reporting, and boot integration possible.

## Daemons and lifecycle state

A daemon is the running process behind a service. The fact that a unit exists does not mean its daemon is currently running.

The Python, JavaScript, C++, and Java implementations represent the lifecycle with states corresponding to systemd's observable service behavior:

| Model state | Meaning |
| --- | --- |
| `inactive` | The service is not currently running. |
| `activating` | Startup is in progress. |
| `active` | The daemon has successfully reached its running state. |
| `deactivating` | Shutdown is in progress. |
| `failed` | Startup or runtime handling has resulted in a failed service state. |

This distinction matters operationally. A service can be installed and configured correctly while remaining inactive because it is disabled, intentionally stopped, waiting for a dependency, or not yet requested.

A daemon also has its own process-level behavior. systemd can supervise the process, observe termination, restart it according to policy, and record lifecycle events. The code models these transitions without launching real host daemons.

## Service configuration

The Python implementation uses `ServiceConfig` to represent a service unit and validates important fields before activation.

It models:

- unit name and description
- `ExecStart`
- working directory
- environment variables
- restart policy
- restart delay
- service user
- startup target
- service dependencies

The generated unit text demonstrates how structured configuration becomes a systemd-style unit.

The implementation intentionally uses absolute executable paths in production-oriented examples. This reduces ambiguity about which executable systemd should invoke and avoids relying on an interactive shell's environment.

The examples also use dedicated users such as `orders`, `metrics`, and `billing`. Running a network daemon as an unnecessary privileged account increases the consequences of a compromise. `User=` provides an explicit identity boundary.

Environment values are useful for non-secret configuration such as `APP_ENV=production` or `LOG_LEVEL=info`. Sensitive credentials should not be casually embedded in ordinary unit files because file permissions, process environments, logs, backups, and administrative access all affect their exposure.

## Dependencies and ordering

The example system has this relationship:

    network-online.target.service
                 |
                 v
         metrics-agent.service
                 |
                 v
           orders-api.service

The orders API also declares the network target directly.

This illustrates a key distinction in systemd dependency modeling. An ordering relationship such as `After=` controls sequence, while dependency relationships determine whether required units must be present or active for the service to operate correctly.

The code models dependency activation before application activation. A missing dependency produces a failure rather than silently starting the dependent service in an invalid state.

In real systemd deployments, dependency semantics can be expressed with directives such as `Requires=`, `Wants=`, `Requisite=`, `After=`, and related unit relationships. These directives have different failure and activation semantics and should not be treated as interchangeable.

## Startup services and boot targets

Startup participation is represented separately from runtime state.

The example uses:

    WantedBy=multi-user.target

and marks the application services as enabled. The simulated boot sequence then considers enabled services for activation.

The database model uses a dedicated `service_startup` table because startup policy is conceptually different from runtime state. A service can be:

    enabled + inactive
    enabled + active
    disabled + inactive
    static + active

A static unit is particularly important. It can participate in dependency-driven activation without being independently enabled in the same way as an ordinary boot service.

This prevents a common conceptual mistake: **enabled does not mean running**. Enablement describes startup wiring; activation describes current runtime state.

## Python implementation

The Python program provides a complete service-management simulator through `ServiceManager`, `SimulatedService`, and `ServiceConfig`.

`ServiceConfig.validate()` enforces unit naming, command presence, restart policy, restart timing, and startup configuration. This models configuration validation before a daemon is activated.

`SimulatedService.start()` resolves declared dependencies through the manager before transitioning from `inactive` to `activating` and finally to `active`. A special `FAIL` executable marker creates a deterministic failure path without executing an arbitrary operating-system command.

`enable()` and `disable()` modify startup policy independently of the running state. `restart()` models controlled shutdown followed by another activation attempt.

`unit_text()` creates a systemd-style unit file from structured configuration. The script writes one candidate unit only into a temporary directory. It does not install it into `/etc/systemd/system`, reload systemd, or alter host services.

The Linux inspection function is deliberately read-only. When running on Linux it can inspect the installed systemd version and list service unit files. Commands capable of changing service state are not executed.

## JavaScript implementation

The JavaScript program takes an event-driven approach because Node.js provides a natural model for service lifecycle events.

`Daemon` extends `EventEmitter`. State changes emit events that the `ServiceManager` observes. This reflects the operational reality that service management involves state transitions and events rather than a single synchronous function call.

`ServiceConfig.toUnitFile()` constructs a systemd-style unit from structured JavaScript objects. The implementation includes basic quoting logic for shell arguments and systemd environment values rather than concatenating every value blindly.

`HealthMonitor` provides asynchronous health evaluation. It accepts functions returning promises and converts their results into operational health records. This demonstrates a useful distinction between **service state** and **application health**. A process may be alive while the application it provides is unhealthy.

The Node.js program writes its generated unit only into the operating system's temporary directory. It does not invoke `systemctl` or modify real service configuration.

## C++ case study

The C++ implementation models a small service-management engine for an operations environment.

`ServiceConfig` owns validated configuration data. `Service` owns mutable runtime state, startup policy, restart count, failure information, and a journal. `ServiceManager` acts as the system-level coordinator.

The case study uses `std::map` for named service lookup, `std::vector` for command arguments and dependencies, `std::optional` for an optional failure reason, and `std::map` for environment variables.

The dependency algorithm is deliberately simple:

    for each declared dependency
        locate the dependency
        activate it if necessary
        reject the dependent service if activation fails

For a dependency graph with `V` services and `E` dependency edges, a traversal-based implementation can operate in approximately `O(V + E)` time when each service and dependency is visited once. A production dependency manager also needs cycle detection and more sophisticated ordering semantics. The case study keeps the graph small while preserving the important operational behavior.

The C++ program uses the special `FAIL` command to model an unsuccessful `ExecStart` without invoking external processes. This provides a deterministic failure scenario while avoiding arbitrary command execution.

The service journal records activation, failure, restart, and shutdown events. This mirrors the operational importance of logs when diagnosing why a daemon did not start or repeatedly failed.

## Java enterprise model

The Java program emphasizes explicit domain modeling and immutable configuration.

`ServiceConfiguration` validates the service identity, execution command, restart delay, startup target, and service account. Its collections are copied using `List.copyOf`, `Map.copyOf`, and `Set.copyOf`, preventing callers from modifying the configuration after construction.

`ManagedDaemon` owns mutable lifecycle state and records `ServiceEvent` records containing an `Instant`, service identity, and message.

`ServiceRegistry` coordinates named services and boot processing. `ServiceHealthPolicy` deliberately treats `ACTIVE` as healthy, making the health rule explicit rather than embedding it into every caller.

The `Capability` enum models the resources that a service may conceptually require, such as network access, filesystem access, or database access. The example keeps these capabilities separate from the service's lifecycle so that resource requirements do not become confused with startup state.

Java's `switch` expression is used for restart-policy translation, and records provide a compact immutable representation of service events.

## SQL data model

The PostgreSQL implementation represents service management as relational data.

`service_units` stores declarative unit configuration. Its constraints enforce:

- `.service` naming
- non-empty execution commands
- non-empty service identities
- non-negative restart delays

`service_environment` represents environment variables separately from the core service row. The primary key prevents duplicate variable names within one service.

`service_dependencies` represents the directed relationship from a service to another unit. This makes dependency queries explicit and allows operational reports to show dependency state.

`service_startup` separates boot participation from service runtime state. This is important because `enabled`, `disabled`, and `static` describe startup semantics rather than whether a daemon is currently running.

`service_runtime` stores current lifecycle state, restart count, failure information, and the last state transition.

`service_events` provides an append-oriented operational history. This makes it possible to inspect the sequence of service events rather than looking only at the latest state.

`service_health_checks` stores application or operational health observations separately from lifecycle state.

## Database integrity and transactions

The schema uses primary keys, foreign keys, uniqueness constraints, and `CHECK` constraints to prevent invalid representations.

For example, this rule ensures a unit has the expected service suffix:

    CHECK (unit_name ~ '\.service$')

The restart-delay constraint prevents nonsensical negative delays:

    CHECK (restart_seconds >= 0)

Foreign keys prevent environment, dependency, runtime, event, and health records from referring to nonexistent service units.

The script also demonstrates a transaction that records a controlled stop. The runtime transition and corresponding service event are committed together. This matters because operational data becomes misleading if a state change succeeds but its audit event is lost, or an event is recorded for a state change that was rolled back.

The final queries expose failed services, unhealthy services, dependency state, startup configuration, environment configuration, and recent operational events.

## Restart behavior

Restart policy belongs to service supervision rather than startup enablement.

The examples distinguish:

| Policy | Meaning in the model |
| --- | --- |
| `no` | Do not automatically restart after termination. |
| `on-failure` | Restart when the service terminates unsuccessfully. |
| `always` | Restart regardless of the termination result, subject to systemd's broader supervision behavior. |

`RestartSec=` controls the delay before a restart attempt.

Automatic restart is useful for transient failures, but it can also hide persistent configuration errors by creating a restart loop. Production operations should examine service status and logs instead of assuming that a restart policy makes a broken service healthy.

## Failure handling

The billing worker deliberately fails during activation.

The failure is represented separately from ordinary inactive state:

    inactive
        |
        | start
        v
    activating
        |
        | ExecStart failure
        v
      failed

A failed service contains an explicit failure reason in all four application-language implementations and in the relational runtime model.

This distinction is operationally valuable. An inactive service might be intentionally stopped, while a failed service indicates that an activation or runtime problem needs investigation.

A dependency failure is propagated to a dependent service in the simulations. This prevents the application from appearing healthy when a required component cannot be activated.

## Service configuration versus startup configuration

These concepts are related but should not be combined into one state.

Service configuration answers:

> How should this daemon run?

It includes the executable, user, environment, working directory, restart policy, and dependencies.

Startup configuration answers:

> Under which boot target should this service be activated automatically?

It includes enablement and the target associated with that enablement.

Runtime state answers a different question:

> What is happening to the daemon right now?

It includes inactive, activating, active, deactivating, and failed states.

Keeping these dimensions separate makes operational diagnosis much clearer.

## Debugging model

When a real Linux service fails, a useful diagnostic sequence is to inspect the unit's configuration, current status, dependency relationships, and journal records.

Typical commands include:

    systemctl status orders-api.service
    systemctl cat orders-api.service
    systemctl list-dependencies orders-api.service
    journalctl -u orders-api.service

The first command gives a compact runtime view. `systemctl cat` exposes the effective unit configuration. Dependency inspection helps determine whether another unit prevents activation. `journalctl` provides service-specific logs and is often essential when `ExecStart` fails.

The learning implementations reproduce these diagnostic concepts with status objects, event journals, failure fields, and dependency queries.

## Common configuration mistakes

A missing or incorrect executable path can cause activation failure even though the unit file itself exists.

Running a service under an unnecessarily privileged account increases the impact of a daemon compromise. The examples therefore use dedicated users for application services.

Assuming `After=` means "start this dependency" is another common mistake. Ordering and dependency requirements are separate concepts in systemd's unit model.

Assuming an enabled service must currently be active also leads to incorrect diagnosis. Enablement controls startup relationships; it does not eliminate the possibility of an intentional stop or a runtime failure.

Aggressive restart policies can produce restart loops. A service that fails immediately after every launch still needs configuration or application-level investigation.

Environment variables should not be treated as a universal secret-management mechanism. Sensitive credentials require stronger access-control and secret-management practices than ordinary non-secret service configuration.

## Production considerations

A production Linux service should have a clearly defined process identity, explicit execution path, predictable working directory, controlled environment, and a restart policy appropriate to its failure behavior.

Dependencies should represent real operational requirements rather than being added merely to force a particular startup order.

Startup enablement should be deliberate. Enabling unnecessary services expands the set of processes that run automatically after boot and increases operational complexity.

Service logs should make failures diagnosable. A restart policy without observable failure information can make a system appear unstable without revealing the underlying cause.

Unit files should be permission-controlled because service configuration can contain operational details and, if badly designed, sensitive information.

Changes to service configuration should be tested before deployment. Syntax correctness alone is insufficient; dependency behavior, privilege boundaries, startup timing, failure recovery, and application health all affect whether a daemon is genuinely operational.

## Performance considerations

Service startup is influenced by dependency structure. A long serial dependency chain can delay availability, while independent services can often start concurrently.

The simulations use straightforward in-memory lookup structures. Python and JavaScript use dictionaries/maps, while C++ uses `std::map` and Java uses `Map` implementations. A production service manager needs additional mechanisms for cycle detection, ordering, concurrent activation, process supervision, timeout handling, resource limits, and failure propagation.

Database queries use indexes on service events, health checks, startup policy, and dependency references because operational queries frequently filter or sort by these fields.

The SQL schema separates current runtime state from historical events. Current state remains cheap to query while the event table can grow independently as operational history accumulates.

## Security considerations

The service account is an important security boundary. Application daemons should normally run with only the privileges required for their workload.

Executable paths should be controlled so that service startup does not unexpectedly select an attacker-controlled executable.

Configuration and environment values should be protected according to their sensitivity. A unit file containing a database password can become a secret-exposure mechanism if its permissions or backups are poorly managed.

Administrative service operations such as starting, stopping, enabling, disabling, and modifying units can affect system availability. The executable demonstrations therefore avoid changing real system services.

The Python Linux inspection path is restricted to read-only systemctl operations. The other implementations are simulations and do not invoke service-management commands.

## Relationship between the four areas

The complete operational chain can be represented as:

    service configuration
            |
            v
       systemd unit
            |
            v
    startup/dependency decision
            |
            v
       daemon activation
            |
            v
       runtime state
            |
            v
    health, logs, and recovery

Configuration defines the intended behavior. systemd interprets the unit and coordinates activation. Startup configuration determines whether the service participates automatically in boot targets. Dependencies constrain activation order and availability. The daemon then enters a runtime state that can be monitored, logged, stopped, restarted, or marked failed.

Treating these as separate but connected mechanisms is the central technical model demonstrated across the five implementations and the relational database.
