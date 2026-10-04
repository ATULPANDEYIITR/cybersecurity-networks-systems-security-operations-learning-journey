import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/*
 * Linux Services enterprise-oriented case study.
 *
 * The application models a service platform used by an operations team.
 * It deliberately separates:
 *
 * - unit configuration
 * - daemon lifecycle
 * - startup policy
 * - dependency rules
 * - health evaluation
 * - operational events
 *
 * No host service is modified.
 */
public class LinuxServicesDemo {

    enum ServiceState {
        INACTIVE,
        ACTIVATING,
        ACTIVE,
        DEACTIVATING,
        FAILED
    }

    enum StartupPolicy {
        DISABLED,
        ENABLED,
        STATIC
    }

    enum RestartPolicy {
        NO,
        ON_FAILURE,
        ALWAYS
    }

    enum Capability {
        NETWORK,
        FILESYSTEM,
        DATABASE
    }

    record ServiceEvent(Instant timestamp, String service, String message) {
        @Override
        public String toString() {
            return timestamp + " " + service + ": " + message;
        }
    }

    static final class ServiceConfiguration {
        private final String unitName;
        private final String description;
        private final List<String> execStart;
        private final String user;
        private final String workingDirectory;
        private final Map<String, String> environment;
        private final Set<Capability> capabilities;
        private final List<String> after;
        private final RestartPolicy restartPolicy;
        private final int restartSeconds;
        private final String wantedBy;

        ServiceConfiguration(
                String unitName,
                String description,
                List<String> execStart,
                String user,
                String workingDirectory,
                Map<String, String> environment,
                Set<Capability> capabilities,
                List<String> after,
                RestartPolicy restartPolicy,
                int restartSeconds,
                String wantedBy) {

            this.unitName = Objects.requireNonNull(unitName);
            this.description = Objects.requireNonNull(description);
            this.execStart = List.copyOf(execStart);
            this.user = user;
            this.workingDirectory = workingDirectory;
            this.environment = Map.copyOf(environment);
            this.capabilities = Set.copyOf(capabilities);
            this.after = List.copyOf(after);
            this.restartPolicy = Objects.requireNonNull(restartPolicy);
            this.restartSeconds = restartSeconds;
            this.wantedBy = Objects.requireNonNull(wantedBy);

            validate();
        }

        void validate() {
            if (!unitName.endsWith(".service")) {
                throw new IllegalArgumentException(
                        "Invalid service unit name: " + unitName);
            }

            if (execStart.isEmpty()) {
                throw new IllegalArgumentException(
                        "ExecStart must contain a command: " + unitName);
            }

            if (restartSeconds < 0) {
                throw new IllegalArgumentException(
                        "restartSeconds cannot be negative: " + unitName);
            }

            if (wantedBy.isBlank()) {
                throw new IllegalArgumentException(
                        "wantedBy cannot be blank: " + unitName);
            }

            if (user == null || user.isBlank()) {
                throw new IllegalArgumentException(
                        "Production service requires an explicit service user: "
                                + unitName);
            }
        }

        String unitName() {
            return unitName;
        }

        List<String> dependencies() {
            return after;
        }

        String unitFile() {
            StringBuilder builder = new StringBuilder();

            builder.append("[Unit]\n");
            builder.append("Description=").append(description).append('\n');

            if (!after.isEmpty()) {
                builder.append("After=")
                        .append(String.join(" ", after))
                        .append('\n');
            }

            builder.append("\n[Service]\n");
            builder.append("Type=simple\n");
            builder.append("ExecStart=")
                    .append(String.join(" ", execStart))
                    .append('\n');
            builder.append("User=").append(user).append('\n');
            builder.append("Restart=")
                    .append(restartPolicyToSystemd())
                    .append('\n');
            builder.append("RestartSec=")
                    .append(restartSeconds)
                    .append('\n');

            if (workingDirectory != null && !workingDirectory.isBlank()) {
                builder.append("WorkingDirectory=")
                        .append(workingDirectory)
                        .append('\n');
            }

            environment.forEach((key, value) ->
                    builder.append("Environment=")
                            .append(key)
                            .append("=")
                            .append(value)
                            .append('\n'));

            builder.append("\n[Install]\n");
            builder.append("WantedBy=").append(wantedBy).append('\n');

            return builder.toString();
        }

        private String restartPolicyToSystemd() {
            return switch (restartPolicy) {
                case NO -> "no";
                case ON_FAILURE -> "on-failure";
                case ALWAYS -> "always";
            };
        }
    }

    static final class ManagedDaemon {
        private final ServiceConfiguration configuration;
        private ServiceState state = ServiceState.INACTIVE;
        private StartupPolicy startupPolicy = StartupPolicy.DISABLED;
        private int restartCount = 0;
        private String failureReason;
        private final List<ServiceEvent> events = new ArrayList<>();

        ManagedDaemon(ServiceConfiguration configuration) {
            this.configuration = configuration;
        }

        String name() {
            return configuration.unitName();
        }

        ServiceState state() {
            return state;
        }

        StartupPolicy startupPolicy() {
            return startupPolicy;
        }

        List<ServiceEvent> events() {
            return Collections.unmodifiableList(events);
        }

        void enable() {
            startupPolicy = StartupPolicy.ENABLED;
            record("enabled for boot target");
        }

        void disable() {
            startupPolicy = StartupPolicy.DISABLED;
            record("disabled from boot target");
        }

        void markStatic() {
            startupPolicy = StartupPolicy.STATIC;
            record("marked static; activation is dependency-driven");
        }

        void start(ServiceRegistry registry) {
            if (state == ServiceState.ACTIVE) {
                record("start ignored because daemon is already active");
                return;
            }

            configuration.validate();

            for (String dependency : configuration.dependencies()) {
                ManagedDaemon required = registry.require(dependency);

                if (required.state() != ServiceState.ACTIVE) {
                    required.start(registry);
                }

                if (required.state() != ServiceState.ACTIVE) {
                    fail("dependency unavailable: " + dependency);
                    return;
                }
            }

            state = ServiceState.ACTIVATING;
            record("entered activating state");

            if ("FAIL".equals(configuration.execStart.get(0))) {
                fail("simulated ExecStart failure");
                return;
            }

            state = ServiceState.ACTIVE;
            failureReason = null;
            record("entered active state");
        }

        void stop() {
            if (state == ServiceState.INACTIVE) {
                record("stop ignored because daemon is already inactive");
                return;
            }

            state = ServiceState.DEACTIVATING;
            record("entered deactivating state");

            state = ServiceState.INACTIVE;
            record("entered inactive state");
        }

        void restart(ServiceRegistry registry) {
            record("restart requested");
            stop();
            restartCount++;
            start(registry);
        }

        void fail(String reason) {
            failureReason = reason;
            state = ServiceState.FAILED;
            record("failed: " + reason);
        }

        private void record(String message) {
            events.add(new ServiceEvent(
                    Instant.now(),
                    configuration.unitName(),
                    message));
        }

        String status() {
            return """
                    Unit: %s
                    State: %s
                    Startup: %s
                    Restart count: %d
                    Failure: %s
                    """.formatted(
                    configuration.unitName(),
                    state,
                    startupPolicy,
                    restartCount,
                    failureReason == null ? "none" : failureReason);
        }
    }

    static final class ServiceRegistry {
        private final Map<String, ManagedDaemon> services = new LinkedHashMap<>();

        void register(ManagedDaemon service) {
            if (services.putIfAbsent(service.name(), service) != null) {
                throw new IllegalArgumentException(
                        "Duplicate service: " + service.name());
            }
        }

        ManagedDaemon require(String name) {
            ManagedDaemon service = services.get(name);

            if (service == null) {
                throw new IllegalArgumentException(
                        "Unknown service: " + name);
            }

            return service;
        }

        void boot() {
            for (ManagedDaemon service : services.values()) {
                if (service.startupPolicy() == StartupPolicy.ENABLED) {
                    service.start(this);
                }
            }
        }

        Map<String, ServiceState> stateSnapshot() {
            Map<String, ServiceState> result = new LinkedHashMap<>();

            for (ManagedDaemon service : services.values()) {
                result.put(service.name(), service.state());
            }

            return Collections.unmodifiableMap(result);
        }
    }

    static final class ServiceHealthPolicy {
        private final Set<ServiceState> healthyStates =
                EnumSet.of(ServiceState.ACTIVE);

        boolean healthy(ManagedDaemon service) {
            return healthyStates.contains(service.state());
        }
    }

    static ServiceConfiguration productionConfiguration(
            String unitName,
            String description,
            List<String> command,
            String user,
            List<String> dependencies,
            RestartPolicy restartPolicy) {

        return new ServiceConfiguration(
                unitName,
                description,
                command,
                user,
                "/opt/" + user,
                new HashMap<>(Map.of(
                        "APP_ENV", "production",
                        "LOG_LEVEL", "info")),
                EnumSet.of(Capability.NETWORK),
                dependencies,
                restartPolicy,
                5,
                "multi-user.target");
    }

    public static void main(String[] args) {
        ServiceRegistry registry = new ServiceRegistry();

        ManagedDaemon networkTarget = new ManagedDaemon(
                new ServiceConfiguration(
                        "network-online.target.service",
                        "Network availability target",
                        List.of("/bin/true"),
                        "root",
                        null,
                        Map.of(),
                        EnumSet.of(Capability.NETWORK),
                        List.of(),
                        RestartPolicy.NO,
                        0,
                        "multi-user.target"));

        networkTarget.markStatic();
        registry.register(networkTarget);

        ManagedDaemon metricsAgent = new ManagedDaemon(
                productionConfiguration(
                        "metrics-agent.service",
                        "Host metrics collection daemon",
                        List.of(
                                "/opt/metrics/bin/agent",
                                "--config",
                                "/etc/metrics/agent.conf"),
                        "metrics",
                        List.of("network-online.target.service"),
                        RestartPolicy.ALWAYS));

        ManagedDaemon ordersApi = new ManagedDaemon(
                productionConfiguration(
                        "orders-api.service",
                        "Orders API daemon",
                        List.of(
                                "/opt/orders/bin/server",
                                "--port",
                                "8080"),
                        "orders",
                        List.of(
                                "network-online.target.service",
                                "metrics-agent.service"),
                        RestartPolicy.ON_FAILURE));

        registry.register(metricsAgent);
        registry.register(ordersApi);

        metricsAgent.enable();
        ordersApi.enable();

        System.out.println("Linux Services enterprise case study");

        System.out.println("\nOrders API unit configuration");
        System.out.println(
                ordersApi.configuration.unitFile());

        System.out.println("State before boot");
        registry.stateSnapshot().forEach(
                (name, state) -> System.out.println(name + " -> " + state));

        System.out.println("\nBoot");
        registry.boot();

        System.out.println("\nState after boot");
        registry.stateSnapshot().forEach(
                (name, state) -> System.out.println(name + " -> " + state));

        ServiceHealthPolicy healthPolicy = new ServiceHealthPolicy();

        System.out.println(
                "\nOrders API health: "
                        + (healthPolicy.healthy(ordersApi)
                        ? "healthy"
                        : "unhealthy"));

        System.out.println("\nRestart");
        ordersApi.restart(registry);
        System.out.println(ordersApi.status());

        System.out.println("Failure handling");
        ManagedDaemon failedWorker = new ManagedDaemon(
                new ServiceConfiguration(
                        "billing-worker.service",
                        "Billing background worker",
                        List.of(
                                "FAIL",
                                "--config",
                                "/etc/billing/worker.conf"),
                        "billing",
                        "/opt/billing",
                        Map.of("APP_ENV", "production"),
                        EnumSet.noneOf(Capability.class),
                        List.of(),
                        RestartPolicy.ON_FAILURE,
                        10,
                        "multi-user.target"));

        registry.register(failedWorker);
        failedWorker.enable();
        failedWorker.start(registry);

        System.out.println(failedWorker.status());

        System.out.println("Health policy result: "
                + (healthPolicy.healthy(failedWorker)
                ? "healthy"
                : "unhealthy"));

        System.out.println("\nRecent orders-api events");
        ordersApi.events().stream()
                .skip(Math.max(0, ordersApi.events().size() - 6))
                .forEach(System.out::println);

        System.out.println("\nEnterprise design distinctions");
        System.out.println(
                "systemd is represented by ServiceRegistry and its boot/lifecycle responsibilities.");
        System.out.println(
                "A daemon is represented by ManagedDaemon and owns runtime state.");
        System.out.println(
                "Service configuration is immutable and validated before activation.");
        System.out.println(
                "Startup policy determines boot participation, while dependencies determine activation order.");
    }
}
