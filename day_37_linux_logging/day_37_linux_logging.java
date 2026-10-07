import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Enterprise Linux Logging Governance Model.
 *
 * Demonstrates a domain-oriented design for:
 * - syslog facilities and severity
 * - authentication events
 * - kernel events
 * - application events
 * - log classification
 * - security-oriented analysis
 * - validation and immutable domain records
 */
public class LinuxLoggingEnterpriseDemo {

    enum Severity {
        EMERG(0),
        ALERT(1),
        CRIT(2),
        ERR(3),
        WARNING(4),
        NOTICE(5),
        INFO(6),
        DEBUG(7);

        private final int code;

        Severity(int code) {
            this.code = code;
        }

        public int code() {
            return code;
        }
    }

    enum Facility {
        KERN(0),
        USER(1),
        DAEMON(3),
        AUTH(4),
        SYSLOG(5),
        CRON(9),
        AUTHPRIV(10),
        LOCAL0(16),
        LOCAL1(17);

        private final int code;

        Facility(int code) {
            this.code = code;
        }

        public int code() {
            return code;
        }

        public int priority(Severity severity) {
            return code * 8 + severity.code();
        }
    }

    enum EventDomain {
        AUTHENTICATION,
        KERNEL,
        APPLICATION
    }

    record LogEvent(
        Instant timestamp,
        String host,
        String service,
        Facility facility,
        Severity severity,
        String message,
        String source,
        Integer pid,
        String user,
        String ip,
        EventDomain domain
    ) {
        LogEvent {
            Objects.requireNonNull(timestamp, "timestamp");
            Objects.requireNonNull(host, "host");
            Objects.requireNonNull(service, "service");
            Objects.requireNonNull(facility, "facility");
            Objects.requireNonNull(severity, "severity");
            Objects.requireNonNull(message, "message");
            Objects.requireNonNull(source, "source");
            Objects.requireNonNull(domain, "domain");

            if (host.isBlank()) {
                throw new IllegalArgumentException("host cannot be blank");
            }

            if (service.isBlank()) {
                throw new IllegalArgumentException("service cannot be blank");
            }

            if (message.isBlank()) {
                throw new IllegalArgumentException("message cannot be blank");
            }

            if (pid != null && pid <= 0) {
                throw new IllegalArgumentException("pid must be positive");
            }
        }

        boolean isAuthenticationFailure() {
            return domain == EventDomain.AUTHENTICATION
                && message.toLowerCase().contains("failed password");
        }

        boolean isKernelFault() {
            return domain == EventDomain.KERNEL
                && (severity.code() <= Severity.ERR.code());
        }
    }

    record SecurityFinding(
        String category,
        String source,
        String evidence,
        Severity severity
    ) {}

    static final class AuthenticationPolicy {
        private final int suspiciousFailureThreshold;

        AuthenticationPolicy(int suspiciousFailureThreshold) {
            if (suspiciousFailureThreshold < 1) {
                throw new IllegalArgumentException(
                    "failure threshold must be positive"
                );
            }
            this.suspiciousFailureThreshold = suspiciousFailureThreshold;
        }

        List<SecurityFinding> evaluate(List<LogEvent> events) {
            Map<String, Integer> failuresByIp = new HashMap<>();

            for (LogEvent event : events) {
                if (!event.isAuthenticationFailure()) {
                    continue;
                }

                String ip = event.ip();

                if (ip == null || ip.isBlank()) {
                    continue;
                }

                failuresByIp.merge(ip, 1, Integer::sum);
            }

            List<SecurityFinding> findings = new ArrayList<>();

            for (Map.Entry<String, Integer> entry : failuresByIp.entrySet()) {
                if (entry.getValue() >= suspiciousFailureThreshold) {
                    findings.add(
                        new SecurityFinding(
                            "Repeated authentication failure",
                            entry.getKey(),
                            entry.getValue()
                                + " SSH authentication failures",
                            Severity.WARNING
                        )
                    );
                }
            }

            return findings;
        }
    }

    static final class KernelPolicy {
        List<SecurityFinding> evaluate(List<LogEvent> events) {
            List<SecurityFinding> findings = new ArrayList<>();

            for (LogEvent event : events) {
                if (!event.isKernelFault()) {
                    continue;
                }

                String message = event.message().toLowerCase();

                if (message.contains("i/o error")
                    || message.contains("nvme")) {
                    findings.add(
                        new SecurityFinding(
                            "Storage fault",
                            event.host(),
                            event.message(),
                            event.severity()
                        )
                    );
                } else if (
                    message.contains("out of memory")
                    || message.contains("oom")
                ) {
                    findings.add(
                        new SecurityFinding(
                            "Memory pressure",
                            event.host(),
                            event.message(),
                            event.severity()
                        )
                    );
                } else {
                    findings.add(
                        new SecurityFinding(
                            "Kernel fault",
                            event.host(),
                            event.message(),
                            event.severity()
                        )
                    );
                }
            }

            return findings;
        }
    }

    static final class LogGovernanceService {
        private final List<LogEvent> events = new ArrayList<>();
        private final AuthenticationPolicy authenticationPolicy;
        private final KernelPolicy kernelPolicy;

        LogGovernanceService(
            AuthenticationPolicy authenticationPolicy,
            KernelPolicy kernelPolicy
        ) {
            this.authenticationPolicy =
                Objects.requireNonNull(authenticationPolicy);
            this.kernelPolicy =
                Objects.requireNonNull(kernelPolicy);
        }

        void ingest(LogEvent event) {
            Objects.requireNonNull(event);

            /*
             * The application layer rejects malformed domain records before
             * they reach analysis. Sensitive fields should also be redacted
             * before ingestion when the source contains credentials or tokens.
             */
            events.add(event);
        }

        List<LogEvent> events() {
            return List.copyOf(events);
        }

        Map<Severity, Long> severityCounts() {
            Map<Severity, Long> result =
                new EnumMap<>(Severity.class);

            for (LogEvent event : events) {
                result.merge(event.severity(), 1L, Long::sum);
            }

            return result;
        }

        Map<EventDomain, Long> domainCounts() {
            Map<EventDomain, Long> result =
                new EnumMap<>(EventDomain.class);

            for (LogEvent event : events) {
                result.merge(event.domain(), 1L, Long::sum);
            }

            return result;
        }

        List<SecurityFinding> findings() {
            List<SecurityFinding> findings = new ArrayList<>();
            findings.addAll(authenticationPolicy.evaluate(events));
            findings.addAll(kernelPolicy.evaluate(events));
            return findings;
        }

        Optional<LogEvent> highestPriorityEvent() {
            return events.stream()
                .min((left, right) -> Integer.compare(
                    left.facility().priority(left.severity()),
                    right.facility().priority(right.severity())
                ));
        }
    }

    static List<LogEvent> sampleEvents() {
        Instant base = Instant.parse("2026-10-07T11:00:00Z");

        return List.of(
            new LogEvent(
                base,
                "prod-web-01",
                "sshd",
                Facility.AUTHPRIV,
                Severity.WARNING,
                "Failed password for invalid user admin from 203.0.113.42",
                "/var/log/auth.log",
                null,
                "admin",
                "203.0.113.42",
                EventDomain.AUTHENTICATION
            ),
            new LogEvent(
                base.plusSeconds(10),
                "prod-web-01",
                "sshd",
                Facility.AUTHPRIV,
                Severity.WARNING,
                "Failed password for root from 203.0.113.42",
                "/var/log/auth.log",
                null,
                "root",
                "203.0.113.42",
                EventDomain.AUTHENTICATION
            ),
            new LogEvent(
                base.plusSeconds(20),
                "prod-web-01",
                "sshd",
                Facility.AUTHPRIV,
                Severity.INFO,
                "Accepted publickey for deploy from 10.10.20.15",
                "/var/log/auth.log",
                null,
                "deploy",
                "10.10.20.15",
                EventDomain.AUTHENTICATION
            ),
            new LogEvent(
                base.plusSeconds(30),
                "prod-web-01",
                "kernel",
                Facility.KERN,
                Severity.ERR,
                "nvme0: I/O error, aborting command",
                "/var/log/kern.log",
                null,
                null,
                null,
                EventDomain.KERNEL
            ),
            new LogEvent(
                base.plusSeconds(40),
                "prod-web-01",
                "kernel",
                Facility.KERN,
                Severity.WARNING,
                "Out of memory: Kill process 2811 (worker)",
                "/var/log/kern.log",
                2811,
                null,
                null,
                EventDomain.KERNEL
            ),
            new LogEvent(
                base.plusSeconds(50),
                "prod-web-01",
                "inventory-api",
                Facility.LOCAL0,
                Severity.ERR,
                "database connection pool exhausted",
                "/var/log/inventory-api.json",
                9021,
                null,
                "192.0.2.44",
                EventDomain.APPLICATION
            ),
            new LogEvent(
                base.plusSeconds(60),
                "prod-web-01",
                "inventory-api",
                Facility.LOCAL0,
                Severity.INFO,
                "request completed status=200 route=/health",
                "/var/log/inventory-api.json",
                9021,
                null,
                "10.10.20.15",
                EventDomain.APPLICATION
            )
        );
    }

    static void printReport(LogGovernanceService service) {
        System.out.println("\nSEVERITY DISTRIBUTION");
        System.out.println("---------------------");

        service.severityCounts().forEach(
            (severity, count) ->
                System.out.println("  " + severity + ": " + count)
        );

        System.out.println("\nEVENT DOMAINS");
        System.out.println("-------------");

        service.domainCounts().forEach(
            (domain, count) ->
                System.out.println("  " + domain + ": " + count)
        );

        System.out.println("\nSECURITY AND OPERATIONS FINDINGS");
        System.out.println("-------------------------------");

        for (SecurityFinding finding : service.findings()) {
            System.out.println(
                "  [" + finding.severity() + "] "
                + finding.category()
                + " | source=" + finding.source()
                + " | " + finding.evidence()
            );
        }

        service.highestPriorityEvent().ifPresent(event ->
            System.out.println(
                "\nHighest-priority event: "
                + event.facility()
                + "/"
                + event.severity()
                + " -> "
                + event.message()
            )
        );
    }

    public static void main(String[] args) {
        System.out.println("LINUX LOGGING ENTERPRISE MODEL");
        System.out.println("==============================");

        System.out.println("\nSYSLOG PRIORITY EXAMPLES");
        System.out.println("------------------------");
        System.out.println(
            "AUTHPRIV/WARNING priority = "
            + Facility.AUTHPRIV.priority(Severity.WARNING)
        );
        System.out.println(
            "KERN/ERR priority = "
            + Facility.KERN.priority(Severity.ERR)
        );
        System.out.println(
            "LOCAL0/INFO priority = "
            + Facility.LOCAL0.priority(Severity.INFO)
        );

        LogGovernanceService service =
            new LogGovernanceService(
                new AuthenticationPolicy(2),
                new KernelPolicy()
            );

        for (LogEvent event : sampleEvents()) {
            service.ingest(event);
        }

        printReport(service);

        System.out.println("\nDOMAIN DESIGN");
        System.out.println("-------------");
        System.out.println(
            "Authentication, kernel, and application records are represented "
            + "as one immutable event type but retain explicit domains. "
            + "Policies then apply domain-specific rules without confusing "
            + "authentication evidence with host faults or application errors."
        );

        System.out.println("\nPRODUCTION CONTROLS");
        System.out.println("-------------------");
        System.out.println(
            "Production logging should enforce retention limits, controlled "
            + "access, timestamp synchronization, sensitive-data redaction, "
            + "rotation, centralized collection, and integrity controls."
        );
    }
}
