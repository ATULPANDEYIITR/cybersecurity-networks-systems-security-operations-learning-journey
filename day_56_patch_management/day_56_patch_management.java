import java.time.Instant;
import java.time.LocalDate;
import java.util.*;
import java.util.function.Predicate;

public class PatchManagementEnterprise {

    enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    enum Environment {
        DEVELOPMENT, STAGING, PRODUCTION
    }

    enum DeploymentState {
        PLANNED, DEPLOYING, VALIDATING, COMPLETED, FAILED, ROLLED_BACK
    }

    interface ValidationRule {
        ValidationResult evaluate(Server server, Patch patch);
    }

    record ValidationResult(boolean passed, String rule, String detail) {}

    record Patch(
        String id,
        String title,
        String component,
        String beforeVersion,
        String afterVersion,
        Severity severity,
        LocalDate releaseDate,
        boolean requiresReboot,
        String checksum
    ) {
        Patch {
            if (id == null || !id.matches("P-\\d{4,}")) {
                throw new ValidationException("Invalid patch ID.");
            }
            if (title == null || title.isBlank() ||
                component == null || component.isBlank()) {
                throw new ValidationException("Patch title and component are required.");
            }
            if (!validVersion(beforeVersion) || !validVersion(afterVersion)) {
                throw new ValidationException("Invalid patch version.");
            }
            if (beforeVersion.equals(afterVersion)) {
                throw new ValidationException("Patch versions must differ.");
            }
            if (severity == null || releaseDate == null) {
                throw new ValidationException("Patch severity and release date are required.");
            }
            if (checksum == null || !checksum.matches("[a-fA-F0-9]{64}")) {
                throw new ValidationException("Checksum must be a SHA-256 hexadecimal value.");
            }
        }

        private static boolean validVersion(String version) {
            return version != null && version.matches("\\d+(?:\\.\\d+){1,3}");
        }
    }

    static final class Server {
        private final String id;
        private final String hostname;
        private final Environment environment;
        private final Map<String, String> versions;
        private boolean online = true;
        private boolean rebootRequired;
        private Instant lastPatched;

        Server(
            String id,
            String hostname,
            Environment environment,
            Map<String, String> versions
        ) {
            if (id == null || id.isBlank() ||
                hostname == null || hostname.isBlank()) {
                throw new ValidationException("Server identity is required.");
            }
            this.id = id;
            this.hostname = hostname;
            this.environment = Objects.requireNonNull(environment);
            this.versions = new HashMap<>(versions);
        }

        String id() {
            return id;
        }

        String hostname() {
            return hostname;
        }

        Environment environment() {
            return environment;
        }

        boolean online() {
            return online;
        }

        boolean rebootRequired() {
            return rebootRequired;
        }

        void setOnline(boolean online) {
            this.online = online;
        }

        void setRebootRequired(boolean rebootRequired) {
            this.rebootRequired = rebootRequired;
        }

        Optional<String> version(String component) {
            return Optional.ofNullable(versions.get(component));
        }

        void updateVersion(String component, String version) {
            versions.put(component, version);
        }

        void markPatched() {
            lastPatched = Instant.now();
        }
    }

    static final class Deployment {
        private final Patch patch;
        private final Server server;
        private DeploymentState state = DeploymentState.PLANNED;
        private final List<ValidationResult> validationResults = new ArrayList<>();

        Deployment(Patch patch, Server server) {
            this.patch = patch;
            this.server = server;
        }

        Patch patch() {
            return patch;
        }

        Server server() {
            return server;
        }

        DeploymentState state() {
            return state;
        }

        List<ValidationResult> validationResults() {
            return List.copyOf(validationResults);
        }

        void addValidationResult(ValidationResult result) {
            validationResults.add(result);
        }

        void transition(DeploymentState next) {
            Map<DeploymentState, Set<DeploymentState>> transitions = Map.of(
                DeploymentState.PLANNED,
                Set.of(DeploymentState.DEPLOYING, DeploymentState.FAILED),
                DeploymentState.DEPLOYING,
                Set.of(DeploymentState.VALIDATING, DeploymentState.FAILED),
                DeploymentState.VALIDATING,
                Set.of(
                    DeploymentState.COMPLETED,
                    DeploymentState.FAILED,
                    DeploymentState.ROLLED_BACK
                ),
                DeploymentState.FAILED,
                Set.of(DeploymentState.ROLLED_BACK),
                DeploymentState.COMPLETED,
                Set.of(),
                DeploymentState.ROLLED_BACK,
                Set.of()
            );

            if (!transitions.get(state).contains(next)) {
                throw new DeploymentException(
                    "Invalid transition: " + state + " -> " + next
                );
            }

            state = next;
        }
    }

    static final class ValidationException extends RuntimeException {
        ValidationException(String message) {
            super(message);
        }
    }

    static final class DeploymentException extends RuntimeException {
        DeploymentException(String message) {
            super(message);
        }
    }

    static final class PatchPolicy {
        private final Set<Environment> allowedEnvironments;
        private final EnumSet<Severity> emergencySeverities;
        private final boolean productionRequiresValidation;

        PatchPolicy(
            Set<Environment> allowedEnvironments,
            EnumSet<Severity> emergencySeverities,
            boolean productionRequiresValidation
        ) {
            this.allowedEnvironments = Set.copyOf(allowedEnvironments);
            this.emergencySeverities = EnumSet.copyOf(emergencySeverities);
            this.productionRequiresValidation = productionRequiresValidation;
        }

        boolean permits(Patch patch, Server server) {
            if (!allowedEnvironments.contains(server.environment())) {
                return false;
            }

            if (server.environment() == Environment.PRODUCTION &&
                productionRequiresValidation) {
                return emergencySeverities.contains(patch.severity())
                    || patch.severity() == Severity.MEDIUM
                    || patch.severity() == Severity.LOW;
            }

            return true;
        }
    }

    static final class PatchService {
        private final Map<String, Patch> patches = new HashMap<>();
        private final Map<String, Server> servers = new HashMap<>();
        private final List<ValidationRule> validationRules = new ArrayList<>();

        void registerPatch(Patch patch) {
            if (patches.putIfAbsent(patch.id(), patch) != null) {
                throw new ValidationException("Duplicate patch: " + patch.id());
            }
        }

        void registerServer(Server server) {
            if (servers.putIfAbsent(server.id(), server) != null) {
                throw new ValidationException("Duplicate server: " + server.id());
            }
        }

        void addValidationRule(ValidationRule rule) {
            validationRules.add(Objects.requireNonNull(rule));
        }

        Deployment createDeployment(
            String patchId,
            String serverId,
            PatchPolicy policy
        ) {
            Patch patch = Optional.ofNullable(patches.get(patchId))
                .orElseThrow(() -> new ValidationException("Unknown patch."));

            Server server = Optional.ofNullable(servers.get(serverId))
                .orElseThrow(() -> new ValidationException("Unknown server."));

            if (!server.online()) {
                throw new DeploymentException("Server is offline.");
            }

            if (!policy.permits(patch, server)) {
                throw new DeploymentException("Patch violates environment policy.");
            }

            String installed = server.version(patch.component()).orElse(null);
            if (!patch.beforeVersion().equals(installed)) {
                throw new DeploymentException(
                    "Installed version " + installed +
                    " does not satisfy prerequisite " + patch.beforeVersion()
                );
            }

            return new Deployment(patch, server);
        }

        void execute(Deployment deployment) {
            Patch patch = deployment.patch();
            Server server = deployment.server();

            String previousVersion =
                server.version(patch.component()).orElseThrow();
            boolean previousRebootState = server.rebootRequired();

            deployment.transition(DeploymentState.DEPLOYING);

            try {
                server.updateVersion(patch.component(), patch.afterVersion());
                server.setRebootRequired(patch.requiresReboot());

                deployment.transition(DeploymentState.VALIDATING);

                for (ValidationRule rule : validationRules) {
                    ValidationResult result = rule.evaluate(server, patch);
                    deployment.addValidationResult(result);

                    if (!result.passed()) {
                        deployment.transition(DeploymentState.FAILED);
                        rollback(
                            deployment,
                            previousVersion,
                            previousRebootState
                        );
                        return;
                    }
                }

                server.setRebootRequired(false);
                server.markPatched();
                deployment.transition(DeploymentState.COMPLETED);

            } catch (RuntimeException ex) {
                if (deployment.state() != DeploymentState.ROLLED_BACK) {
                    if (deployment.state() != DeploymentState.FAILED) {
                        deployment.transition(DeploymentState.FAILED);
                    }
                    rollback(
                        deployment,
                        previousVersion,
                        previousRebootState
                    );
                }
                throw ex;
            }
        }

        private void rollback(
            Deployment deployment,
            String previousVersion,
            boolean previousRebootState
        ) {
            Server server = deployment.server();
            Patch patch = deployment.patch();

            server.updateVersion(patch.component(), previousVersion);
            server.setRebootRequired(previousRebootState);

            deployment.transition(DeploymentState.ROLLED_BACK);
        }

        List<Patch> emergencyPatches() {
            return patches.values()
                .stream()
                .filter(p ->
                    p.severity() == Severity.CRITICAL ||
                    p.severity() == Severity.HIGH
                )
                .sorted(
                    Comparator.comparing(
                        Patch::severity,
                        Comparator.comparingInt(Severity::ordinal)
                    )
                )
                .toList();
        }
    }

    static String demoChecksum(String value) {
        // Fixed hexadecimal data keeps this standalone example deterministic.
        // Real package verification must use a cryptographic SHA-256 implementation.
        return String.format(
            "%064x",
            Math.abs(value.hashCode())
        );
    }

    public static void main(String[] args) {
        PatchService service = new PatchService();

        Patch criticalPatch = new Patch(
            "P-4001",
            "OpenSSL critical security update",
            "openssl",
            "3.0.12",
            "3.0.17",
            Severity.CRITICAL,
            LocalDate.now(),
            false,
            demoChecksum("openssl-3.0.17-security")
        );

        service.registerPatch(criticalPatch);

        service.registerServer(
            new Server(
                "srv-401",
                "identity-prod-01",
                Environment.PRODUCTION,
                Map.of(
                    "openssl", "3.0.12",
                    "linux-kernel", "6.1.70"
                )
            )
        );

        service.addValidationRule(
            (server, patch) -> new ValidationResult(
                server.online(),
                "host_online",
                "Production host must remain reachable."
            )
        );

        service.addValidationRule(
            (server, patch) -> new ValidationResult(
                server.version(patch.component())
                    .map(patch.afterVersion()::equals)
                    .orElse(false),
                "version_check",
                "Installed version must equal the approved target."
            )
        );

        service.addValidationRule(
            (server, patch) -> new ValidationResult(
                !server.rebootRequired(),
                "reboot_check",
                "Reboot requirement must be cleared before completion."
            )
        );

        PatchPolicy policy = new PatchPolicy(
            Set.of(Environment.STAGING, Environment.PRODUCTION),
            EnumSet.of(Severity.HIGH, Severity.CRITICAL),
            true
        );

        Deployment deployment =
            service.createDeployment("P-4001", "srv-401", policy);

        service.execute(deployment);

        System.out.println(
            "Deployment state: " + deployment.state()
        );

        deployment.validationResults().forEach(result ->
            System.out.println(
                "[" + (result.passed() ? "PASS" : "FAIL") + "] " +
                result.rule() + " - " + result.detail()
            )
        );

        System.out.println("\nEmergency patches:");
        service.emergencyPatches().forEach(patch ->
            System.out.println(
                patch.id() + " " +
                patch.title() + " [" +
                patch.severity() + "]"
            )
        );

        try {
            service.createDeployment(
                "P-4001",
                "srv-401",
                new PatchPolicy(
                    Set.of(Environment.STAGING),
                    EnumSet.of(Severity.CRITICAL),
                    true
                )
            );
        } catch (DeploymentException ex) {
            System.out.println(
                "\nExpected policy failure: " + ex.getMessage()
            );
        }
    }
}
