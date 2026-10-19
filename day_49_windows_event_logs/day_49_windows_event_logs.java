import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/*
 * Windows Event Log Enterprise Governance Model
 *
 * The model separates event channels, authentication outcomes, PowerShell
 * telemetry, and high-impact security events. Policy objects determine how
 * evidence is classified instead of embedding all decisions in main().
 */
public class WindowsEventLogs {

    enum Channel {
        SECURITY,
        SYSTEM,
        APPLICATION,
        POWERSHELL
    }

    enum Severity {
        INFORMATIONAL,
        WARNING,
        CRITICAL
    }

    enum AuthenticationOutcome {
        SUCCESS,
        FAILURE,
        NOT_AUTHENTICATION
    }

    record WindowsEvent(
        long recordId,
        Channel channel,
        int eventId,
        Instant timestamp,
        String computer,
        String user,
        String sourceIp,
        String message
    ) {
        WindowsEvent {
            if (recordId <= 0) {
                throw new IllegalArgumentException("recordId must be positive");
            }
            if (eventId < 0) {
                throw new IllegalArgumentException("eventId cannot be negative");
            }
            if (timestamp == null) {
                throw new IllegalArgumentException("timestamp is required");
            }
            if (computer == null || computer.isBlank()) {
                throw new IllegalArgumentException("computer is required");
            }

            if (eventId == 4625 && (sourceIp == null || sourceIp.isBlank())) {
                throw new IllegalArgumentException(
                    "4625 requires source IP evidence"
                );
            }
        }

        AuthenticationOutcome authenticationOutcome() {
            return switch (eventId) {
                case 4624 -> AuthenticationOutcome.SUCCESS;
                case 4625, 4771 -> AuthenticationOutcome.FAILURE;
                default -> AuthenticationOutcome.NOT_AUTHENTICATION;
            };
        }

        boolean isPowerShellScriptBlock() {
            return channel == Channel.POWERSHELL && eventId == 4104;
        }

        boolean affectsAuditIntegrity() {
            return channel == Channel.SECURITY && eventId == 1102;
        }

        boolean indicatesServiceInstallation() {
            return eventId == 7045;
        }
    }

    record Finding(
        Severity severity,
        String rule,
        String evidence
    ) {}

    interface EventPolicy {
        List<Finding> evaluate(List<WindowsEvent> events);
    }

    static final class AuthenticationPolicy implements EventPolicy {
        private final int failureThreshold;

        AuthenticationPolicy(int failureThreshold) {
            if (failureThreshold < 1) {
                throw new IllegalArgumentException(
                    "failure threshold must be positive"
                );
            }
            this.failureThreshold = failureThreshold;
        }

        @Override
        public List<Finding> evaluate(List<WindowsEvent> events) {
            Map<String, Integer> failuresByUserAndIp = new HashMap<>();

            for (WindowsEvent event : events) {
                if (event.authenticationOutcome() == AuthenticationOutcome.FAILURE) {
                    String key = event.user() + "|" + event.sourceIp();
                    failuresByUserAndIp.merge(key, 1, Integer::sum);
                }
            }

            List<Finding> findings = new ArrayList<>();

            for (var entry : failuresByUserAndIp.entrySet()) {
                if (entry.getValue() >= failureThreshold) {
                    findings.add(new Finding(
                        Severity.WARNING,
                        "Authentication failure concentration",
                        entry.getKey() + " failures=" + entry.getValue()
                    ));
                }
            }

            return findings;
        }
    }

    static final class AuditIntegrityPolicy implements EventPolicy {
        @Override
        public List<Finding> evaluate(List<WindowsEvent> events) {
            List<Finding> findings = new ArrayList<>();

            for (WindowsEvent event : events) {
                if (event.affectsAuditIntegrity()) {
                    findings.add(new Finding(
                        Severity.CRITICAL,
                        "Security audit log cleared",
                        "record=" + event.recordId()
                            + " user=" + event.user()
                    ));
                }
            }

            return findings;
        }
    }

    static final class PersistencePolicy implements EventPolicy {
        @Override
        public List<Finding> evaluate(List<WindowsEvent> events) {
            List<Finding> findings = new ArrayList<>();

            for (WindowsEvent event : events) {
                if (event.indicatesServiceInstallation()) {
                    findings.add(new Finding(
                        Severity.CRITICAL,
                        "Service installation",
                        event.message()
                    ));
                }
            }

            return findings;
        }
    }

    static final class PowerShellTelemetryPolicy implements EventPolicy {
        @Override
        public List<Finding> evaluate(List<WindowsEvent> events) {
            List<Finding> findings = new ArrayList<>();

            for (WindowsEvent event : events) {
                if (event.isPowerShellScriptBlock()) {
                    findings.add(new Finding(
                        Severity.INFORMATIONAL,
                        "PowerShell script block recorded",
                        "user=" + event.user()
                    ));
                }
            }

            return findings;
        }
    }

    static final class GovernanceService {
        private final List<EventPolicy> policies;

        GovernanceService(List<EventPolicy> policies) {
            this.policies = List.copyOf(policies);
        }

        List<Finding> evaluate(List<WindowsEvent> events) {
            List<Finding> findings = new ArrayList<>();

            for (EventPolicy policy : policies) {
                findings.addAll(policy.evaluate(events));
            }

            return List.copyOf(findings);
        }
    }

    static Map<Channel, Long> channelCounts(List<WindowsEvent> events) {
        Map<Channel, Long> counts = new EnumMap<>(Channel.class);

        for (WindowsEvent event : events) {
            counts.merge(event.channel(), 1L, Long::sum);
        }

        return counts;
    }

    static Set<String> authenticatedSources(List<WindowsEvent> events) {
        Set<String> sources = new HashSet<>();

        for (WindowsEvent event : events) {
            if (event.eventId() == 4624 && event.sourceIp() != null) {
                sources.add(event.sourceIp());
            }
        }

        return Set.copyOf(sources);
    }

    public static void main(String[] args) {
        List<WindowsEvent> events = List.of(
            new WindowsEvent(
                1, Channel.SECURITY, 4624,
                Instant.parse("2026-10-19T05:00:00Z"),
                "WS-101", "alice", "10.10.20.50",
                "LogonType=10"
            ),
            new WindowsEvent(
                2, Channel.SECURITY, 4625,
                Instant.parse("2026-10-19T05:01:00Z"),
                "WS-101", "administrator", "10.10.20.88",
                "Status=0xC000006D"
            ),
            new WindowsEvent(
                3, Channel.SECURITY, 4625,
                Instant.parse("2026-10-19T05:01:30Z"),
                "WS-101", "administrator", "10.10.20.88",
                "Status=0xC000006D"
            ),
            new WindowsEvent(
                4, Channel.SECURITY, 4625,
                Instant.parse("2026-10-19T05:02:00Z"),
                "WS-101", "administrator", "10.10.20.88",
                "Status=0xC000006D"
            ),
            new WindowsEvent(
                5, Channel.SECURITY, 1102,
                Instant.parse("2026-10-19T05:03:00Z"),
                "WS-101", "administrator", null,
                "Security audit log was cleared"
            ),
            new WindowsEvent(
                6, Channel.SYSTEM, 7045,
                Instant.parse("2026-10-19T05:04:00Z"),
                "WS-101", "SYSTEM", null,
                "RemoteSupport service installed"
            ),
            new WindowsEvent(
                7, Channel.APPLICATION, 1001,
                Instant.parse("2026-10-19T05:04:30Z"),
                "WS-101", "alice", null,
                "Application crash: inventory.exe"
            ),
            new WindowsEvent(
                8, Channel.POWERSHELL, 4104,
                Instant.parse("2026-10-19T05:05:00Z"),
                "WS-101", "alice", null,
                "Get-Process; Get-Service"
            )
        );

        GovernanceService service = new GovernanceService(List.of(
            new AuthenticationPolicy(3),
            new AuditIntegrityPolicy(),
            new PersistencePolicy(),
            new PowerShellTelemetryPolicy()
        ));

        System.out.println("Windows Event Log Enterprise Governance");
        System.out.println("========================================");

        System.out.println("\nChannel distribution");
        channelCounts(events).forEach(
            (channel, count) -> System.out.println("  " + channel + ": " + count)
        );

        System.out.println("\nAuthenticated source addresses");
        authenticatedSources(events).forEach(
            source -> System.out.println("  " + source)
        );

        System.out.println("\nPolicy findings");
        for (Finding finding : service.evaluate(events)) {
            System.out.println(
                "  [" + finding.severity() + "] "
                + finding.rule()
                + " -> "
                + finding.evidence()
            );
        }

        /*
         * The domain model keeps policy decisions separate from event storage.
         * A new policy can therefore evaluate the same normalized events
         * without changing WindowsEvent or the existing policy implementations.
         */
    }
}
