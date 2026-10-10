import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Enterprise-oriented Linux security monitoring model.
 * Compile: javac LinuxSecurityMonitor.java
 * Run: java LinuxSecurityMonitor
 *
 * Synthetic telemetry only. The program does not change host security settings.
 */
public class LinuxSecurityMonitor {

    enum Severity {
        INFO, LOW, MEDIUM, HIGH, CRITICAL
    }

    enum AuthenticationOutcome {
        SUCCESS, FAILURE, INVALID
    }

    enum PersistenceKind {
        SYSTEMD_UNIT, CRON_ENTRY, AUTHORIZED_KEY, AUTOSTART_ENTRY
    }

    record ProcessSnapshot(
            int pid,
            int parentPid,
            int uid,
            String name,
            String executable,
            String commandLine,
            long effectiveCapabilities) {

        ProcessSnapshot {
            if (pid <= 0 || parentPid < 0 || uid < 0) {
                throw new IllegalArgumentException("Invalid process identity");
            }
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(executable, "executable");
            Objects.requireNonNull(commandLine, "commandLine");
        }
    }

    record NetworkListener(
            String protocol,
            String state,
            String localAddress,
            int port,
            Integer pid,
            String processName) {

        NetworkListener {
            Objects.requireNonNull(protocol, "protocol");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(localAddress, "localAddress");
            Objects.requireNonNull(processName, "processName");
            if (port < 0 || port > 65535) {
                throw new IllegalArgumentException("Port must be between 0 and 65535");
            }
        }

        boolean wildcardBound() {
            return localAddress.equals("0.0.0.0")
                    || localAddress.equals("::")
                    || localAddress.equals("*");
        }
    }

    record AuthenticationEvent(
            Instant timestamp,
            String username,
            String sourceAddress,
            AuthenticationOutcome outcome,
            int precedingFailures) {

        AuthenticationEvent {
            Objects.requireNonNull(timestamp, "timestamp");
            Objects.requireNonNull(username, "username");
            Objects.requireNonNull(sourceAddress, "sourceAddress");
            Objects.requireNonNull(outcome, "outcome");
            if (precedingFailures < 0) {
                throw new IllegalArgumentException("Failure count cannot be negative");
            }
        }
    }

    record PersistenceArtifact(
            PersistenceKind kind,
            String path,
            String owner,
            boolean worldWritable,
            boolean enabled,
            String command) {

        PersistenceArtifact {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(owner, "owner");
            Objects.requireNonNull(command, "command");
        }
    }

    record Finding(
            Severity severity,
            String category,
            String title,
            Map<String, String> evidence,
            String recommendation) {

        Finding {
            Objects.requireNonNull(severity, "severity");
            Objects.requireNonNull(category, "category");
            Objects.requireNonNull(title, "title");
            evidence = Map.copyOf(evidence);
            Objects.requireNonNull(recommendation, "recommendation");
        }
    }

    record ReviewPolicy(
            int authenticationFailureThreshold,
            boolean flagTemporaryExecutables,
            boolean flagWildcardListeners,
            boolean inspectPersistenceArtifacts) {

        ReviewPolicy {
            if (authenticationFailureThreshold < 1) {
                throw new IllegalArgumentException("Failure threshold must be positive");
            }
        }
    }

    static final class MonitoringService {
        private final ReviewPolicy policy;

        MonitoringService(ReviewPolicy policy) {
            this.policy = Objects.requireNonNull(policy, "policy");
        }

        List<Finding> inspectProcesses(List<ProcessSnapshot> processes) {
            List<Finding> findings = new ArrayList<>();
            Set<Integer> pids = new HashSet<>();

            for (ProcessSnapshot process : processes) {
                if (!pids.add(process.pid())) {
                    throw new IllegalArgumentException("Duplicate PID: " + process.pid());
                }
            }

            for (ProcessSnapshot process : processes) {
                if (policy.flagTemporaryExecutables()
                        && (process.executable().startsWith("/tmp/")
                        || process.executable().startsWith("/dev/shm/"))) {
                    findings.add(new Finding(
                            Severity.HIGH,
                            "process",
                            "Executable resides in a temporary directory",
                            Map.of(
                                    "pid", Integer.toString(process.pid()),
                                    "name", process.name(),
                                    "executable", process.executable()),
                            "Validate executable provenance, file hash, permissions, and process ancestry."));
                }

                if (process.uid() == 0
                        && (process.commandLine().contains("curl ")
                        || process.commandLine().contains("wget ")
                        || process.commandLine().contains("nc "))) {
                    findings.add(new Finding(
                            Severity.MEDIUM,
                            "process",
                            "Privileged process invokes a network utility",
                            Map.of(
                                    "pid", Integer.toString(process.pid()),
                                    "command", process.commandLine()),
                            "Confirm the command, destination, parent process, and operational authorization."));
                }

                if (process.effectiveCapabilities() != 0L) {
                    findings.add(new Finding(
                            Severity.LOW,
                            "process",
                            "Effective capabilities require least-privilege review",
                            Map.of(
                                    "pid", Integer.toString(process.pid()),
                                    "capabilities", Long.toUnsignedString(
                                            process.effectiveCapabilities(), 16)),
                            "Compare effective capabilities with the approved service policy."));
                }
            }
            return findings;
        }

        List<Finding> inspectNetwork(List<NetworkListener> listeners) {
            List<Finding> findings = new ArrayList<>();

            for (NetworkListener listener : listeners) {
                if (!listener.state().equalsIgnoreCase("LISTEN")) {
                    continue;
                }

                Severity severity = Severity.INFO;
                String title = "Review listener ownership and intended exposure";

                if (listener.port() == 2375) {
                    severity = Severity.HIGH;
                    title = "Docker API listener requires exposure review";
                } else if (Set.of(3306, 5432, 6379, 27017).contains(listener.port())) {
                    severity = Severity.MEDIUM;
                    title = "Database or cache listener requires network review";
                } else if (Set.of(4444, 5555, 31337).contains(listener.port())) {
                    severity = Severity.MEDIUM;
                    title = "Unusual listening port requires process attribution";
                } else if (listener.port() == 22) {
                    severity = Severity.LOW;
                    title = "SSH listener requires authentication-policy review";
                }

                if (policy.flagWildcardListeners() && listener.wildcardBound()
                        && severity.ordinal() < Severity.MEDIUM.ordinal()) {
                    severity = Severity.MEDIUM;
                    title = "Wildcard-bound listener requires exposure review";
                }

                Map<String, String> evidence = new HashMap<>();
                evidence.put("protocol", listener.protocol());
                evidence.put("localAddress", listener.localAddress());
                evidence.put("port", Integer.toString(listener.port()));
                evidence.put("process", listener.processName());
                evidence.put("pid", listener.pid() == null
                        ? "unknown" : listener.pid().toString());

                findings.add(new Finding(
                        severity, "network", title, evidence,
                        "Verify process attribution, firewall policy, service authentication, and network reachability."));
            }
            return findings;
        }

        List<Finding> inspectAuthentication(List<AuthenticationEvent> events) {
            List<Finding> findings = new ArrayList<>();
            Map<String, Integer> bySource = new HashMap<>();
            Map<String, Integer> byUser = new HashMap<>();

            // Sort a copy so out-of-order ingestion does not silently distort
            // temporal correlation. A production system also needs window boundaries.
            List<AuthenticationEvent> ordered = new ArrayList<>(events);
            ordered.sort(Comparator.comparing(AuthenticationEvent::timestamp));

            for (AuthenticationEvent event : ordered) {
                if (event.outcome() == AuthenticationOutcome.FAILURE
                        || event.outcome() == AuthenticationOutcome.INVALID) {
                    bySource.merge(event.sourceAddress(), 1, Integer::sum);
                    byUser.merge(event.username(), 1, Integer::sum);
                }

                if (event.outcome() == AuthenticationOutcome.SUCCESS
                        && event.precedingFailures() >= policy.authenticationFailureThreshold()) {
                    findings.add(new Finding(
                            Severity.HIGH,
                            "authentication",
                            "Successful authentication follows repeated failures",
                            Map.of(
                                    "username", event.username(),
                                    "sourceAddress", event.sourceAddress(),
                                    "precedingFailures", Integer.toString(event.precedingFailures()),
                                    "timestamp", event.timestamp().toString()),
                            "Validate MFA, session context, account ownership, and endpoint activity."));
                }
            }

            bySource.forEach((source, count) -> {
                if (count >= policy.authenticationFailureThreshold()) {
                    findings.add(new Finding(
                            count >= policy.authenticationFailureThreshold() * 2
                                    ? Severity.HIGH : Severity.MEDIUM,
                            "authentication",
                            "Repeated failures from an authentication source",
                            Map.of("sourceAddress", source, "count", Integer.toString(count)),
                            "Correlate with identity-provider and network records before taking action."));
                }
            });

            byUser.forEach((username, count) -> {
                if (count >= policy.authenticationFailureThreshold()) {
                    findings.add(new Finding(
                            Severity.MEDIUM,
                            "authentication",
                            "Repeated failures against an account",
                            Map.of("username", username, "count", Integer.toString(count)),
                            "Distinguish password spraying from stale credentials or legitimate mistakes."));
                }
            });

            return findings;
        }

        List<Finding> inspectPersistence(List<PersistenceArtifact> artifacts) {
            List<Finding> findings = new ArrayList<>();
            if (!policy.inspectPersistenceArtifacts()) {
                return findings;
            }

            for (PersistenceArtifact artifact : artifacts) {
                if (!artifact.enabled()) {
                    continue;
                }

                if (artifact.worldWritable()) {
                    findings.add(new Finding(
                            Severity.HIGH,
                            "persistence",
                            "World-writable persistence artifact",
                            Map.of(
                                    "kind", artifact.kind().name(),
                                    "path", artifact.path(),
                                    "owner", artifact.owner()),
                            "Review file ownership, write permissions, content, and authorized change records."));
                }

                if (artifact.path().startsWith("/tmp/")
                        || artifact.path().startsWith("/dev/shm/")) {
                    findings.add(new Finding(
                            Severity.MEDIUM,
                            "persistence",
                            "Persistence entry references a temporary path",
                            Map.of(
                                    "kind", artifact.kind().name(),
                                    "path", artifact.path(),
                                    "command", artifact.command()),
                            "Verify whether the target is expected and trace its origin."));
                }
            }
            return findings;
        }
    }

    static void printReport(List<Finding> findings) {
        EnumMap<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            counts.put(severity, 0);
        }

        List<Finding> ordered = new ArrayList<>(findings);
        ordered.sort(Comparator.comparingInt(
                (Finding finding) -> finding.severity().ordinal()).reversed());

        System.out.println("Linux Security Monitoring Report");
        for (Finding finding : ordered) {
            counts.merge(finding.severity(), 1, Integer::sum);
            System.out.printf("[%s] %s: %s%n",
                    finding.severity(), finding.category(), finding.title());
            System.out.println("  Evidence: " + finding.evidence());
            System.out.println("  Recommendation: " + finding.recommendation());
        }

        System.out.println("\nSeverity totals");
        counts.forEach((severity, count) ->
                System.out.printf("%s: %d%n", severity, count));
    }

    public static void main(String[] args) {
        ReviewPolicy policy = new ReviewPolicy(5, true, true, true);
        MonitoringService service = new MonitoringService(policy);

        List<ProcessSnapshot> processes = List.of(
                new ProcessSnapshot(401, 1, 0, "curl", "/tmp/curl",
                        "curl https://example.invalid/payload", 0L),
                new ProcessSnapshot(512, 1, 0, "sshd", "/usr/sbin/sshd",
                        "/usr/sbin/sshd -D", 0L),
                new ProcessSnapshot(720, 1, 0, "dockerd", "/usr/bin/dockerd",
                        "/usr/bin/dockerd", 1L << 21));

        List<NetworkListener> listeners = List.of(
                new NetworkListener("tcp", "LISTEN", "0.0.0.0", 2375, 720, "dockerd"),
                new NetworkListener("tcp", "LISTEN", "127.0.0.1", 5432, 730, "postgres"),
                new NetworkListener("tcp", "LISTEN", "0.0.0.0", 22, 512, "sshd"));

        Instant base = Instant.parse("2026-10-10T06:00:00Z");
        List<AuthenticationEvent> authenticationEvents = new ArrayList<>();
        for (int index = 0; index < 5; index++) {
            authenticationEvents.add(new AuthenticationEvent(
                    base.plusSeconds(index),
                    "admin",
                    "203.0.113.44",
                    AuthenticationOutcome.FAILURE,
                    0));
        }
        authenticationEvents.add(new AuthenticationEvent(
                base.plusSeconds(6),
                "admin",
                "203.0.113.44",
                AuthenticationOutcome.SUCCESS,
                5));

        List<PersistenceArtifact> artifacts = List.of(
                new PersistenceArtifact(
                        PersistenceKind.SYSTEMD_UNIT,
                        "/etc/systemd/system/worker.service",
                        "root", true, true, "/tmp/worker"),
                new PersistenceArtifact(
                        PersistenceKind.CRON_ENTRY,
                        "/etc/cron.d/backup",
                        "root", false, true, "/usr/local/sbin/backup"));

        List<Finding> findings = new ArrayList<>();
        findings.addAll(service.inspectProcesses(processes));
        findings.addAll(service.inspectNetwork(listeners));
        findings.addAll(service.inspectAuthentication(authenticationEvents));
        findings.addAll(service.inspectPersistence(artifacts));

        printReport(findings);
    }
}
