import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class WindowsSecurityMonitor {

    enum EventType {
        SUCCESSFUL_LOGON(4624),
        FAILED_LOGON(4625),
        LOGOFF(4634),
        USER_LOGOFF(4647),
        SPECIAL_PRIVILEGES(4672),
        PROCESS_CREATED(4688),
        ACCOUNT_CREATED(4720),
        ACCOUNT_ENABLED(4722),
        ACCOUNT_DISABLED(4725),
        ACCOUNT_DELETED(4726),
        ACCOUNT_CHANGED(4738),
        ACCOUNT_LOCKED(4740),
        UNKNOWN(-1);

        private final int id;

        EventType(int id) {
            this.id = id;
        }

        static EventType fromId(int id) {
            for (EventType type : values()) {
                if (type.id == id) {
                    return type;
                }
            }
            return UNKNOWN;
        }
    }

    enum Severity {
        LOW,
        MEDIUM,
        HIGH
    }

    record SecurityEvent(
        int id,
        Instant timestamp,
        String computer,
        String subjectUser,
        String targetUser,
        String sourceIp,
        String processName,
        Integer processId,
        Integer logonType,
        String privilege
    ) {
        SecurityEvent {
            if (id <= 0) {
                throw new IllegalArgumentException("Event ID must be positive");
            }
            Objects.requireNonNull(timestamp, "timestamp");
            requireText(computer, "computer");
            requireText(subjectUser, "subjectUser");

            if (sourceIp != null && !isValidIpv4(sourceIp)) {
                throw new IllegalArgumentException(
                    "Invalid IPv4 address: " + sourceIp
                );
            }

            if (logonType != null && logonType < 0) {
                throw new IllegalArgumentException(
                    "logonType cannot be negative"
                );
            }
        }

        EventType type() {
            return EventType.fromId(id);
        }

        String effectiveUser() {
            return targetUser != null ? targetUser : subjectUser;
        }

        private static void requireText(String value, String field) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(
                    field + " is required"
                );
            }
        }

        private static boolean isValidIpv4(String value) {
            String[] parts = value.split("\\.", -1);
            if (parts.length != 4) {
                return false;
            }

            for (String part : parts) {
                if (!part.matches("\\d+")) {
                    return false;
                }
                int number = Integer.parseInt(part);
                if (number < 0 || number > 255) {
                    return false;
                }
            }

            return true;
        }
    }

    record Alert(
        Severity severity,
        String rule,
        Instant timestamp,
        String computer,
        String user,
        String evidence
    ) {}

    interface DetectionRule {
        List<Alert> evaluate(List<SecurityEvent> events);
    }

    static final class FailedLogonRule implements DetectionRule {
        private static final Duration WINDOW = Duration.ofMinutes(5);
        private static final int THRESHOLD = 3;

        @Override
        public List<Alert> evaluate(List<SecurityEvent> events) {
            Map<String, ArrayDeque<SecurityEvent>> byUser = new HashMap<>();
            List<Alert> alerts = new ArrayList<>();

            for (SecurityEvent event : events) {
                if (event.type() != EventType.FAILED_LOGON) {
                    continue;
                }

                String user = event.effectiveUser();
                ArrayDeque<SecurityEvent> queue =
                    byUser.computeIfAbsent(user, ignored -> new ArrayDeque<>());

                queue.addLast(event);

                while (!queue.isEmpty() &&
                       Duration.between(
                           queue.peekFirst().timestamp(),
                           event.timestamp()
                       ).compareTo(WINDOW) > 0) {
                    queue.removeFirst();
                }

                if (queue.size() >= THRESHOLD) {
                    alerts.add(new Alert(
                        Severity.HIGH,
                        "failed_logon_burst",
                        event.timestamp(),
                        event.computer(),
                        user,
                        queue.size() +
                            " failed logons within five minutes"
                    ));
                    queue.clear();
                }
            }

            return alerts;
        }
    }

    static final class PrivilegeRule implements DetectionRule {
        private static final Set<String> INTERPRETERS = Set.of(
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe"
        );

        @Override
        public List<Alert> evaluate(List<SecurityEvent> events) {
            List<Alert> alerts = new ArrayList<>();

            for (SecurityEvent event : events) {
                if (event.type() == EventType.SPECIAL_PRIVILEGES) {
                    Severity severity =
                        event.privilege() != null &&
                        event.privilege()
                            .toLowerCase()
                            .contains("debug")
                        ? Severity.HIGH
                        : Severity.MEDIUM;

                    alerts.add(new Alert(
                        severity,
                        "special_privilege_assignment",
                        event.timestamp(),
                        event.computer(),
                        event.effectiveUser(),
                        event.privilege() == null
                            ? "special privilege"
                            : event.privilege()
                    ));
                }

                if (
                    event.type() == EventType.PROCESS_CREATED &&
                    event.processName() != null &&
                    INTERPRETERS.contains(
                        event.processName().toLowerCase()
                    )
                ) {
                    alerts.add(new Alert(
                        Severity.MEDIUM,
                        "script_interpreter_process",
                        event.timestamp(),
                        event.computer(),
                        event.effectiveUser(),
                        event.processName() +
                            " PID=" +
                            event.processId()
                    ));
                }
            }

            return alerts;
        }
    }

    static final class AccountActivityRule implements DetectionRule {
        private static final Set<EventType> ACCOUNT_EVENTS =
            EnumSet.of(
                EventType.ACCOUNT_CREATED,
                EventType.ACCOUNT_ENABLED,
                EventType.ACCOUNT_DISABLED,
                EventType.ACCOUNT_DELETED,
                EventType.ACCOUNT_CHANGED
            );

        @Override
        public List<Alert> evaluate(List<SecurityEvent> events) {
            List<Alert> alerts = new ArrayList<>();

            for (SecurityEvent event : events) {
                if (!ACCOUNT_EVENTS.contains(event.type())) {
                    continue;
                }

                Severity severity =
                    event.type() == EventType.ACCOUNT_CREATED ||
                    event.type() == EventType.ACCOUNT_ENABLED
                        ? Severity.HIGH
                        : Severity.MEDIUM;

                alerts.add(new Alert(
                    severity,
                    "account_activity",
                    event.timestamp(),
                    event.computer(),
                    event.subjectUser(),
                    event.type() +
                        " target=" +
                        event.effectiveUser()
                ));
            }

            return alerts;
        }
    }

    static final class PrivilegedLogonRule implements DetectionRule {
        @Override
        public List<Alert> evaluate(List<SecurityEvent> events) {
            List<Alert> alerts = new ArrayList<>();

            for (SecurityEvent event : events) {
                if (
                    event.type() == EventType.SUCCESSFUL_LOGON &&
                    event.logonType() != null &&
                    Set.of(2, 10, 11).contains(event.logonType()) &&
                    Set.of(
                        "admin",
                        "administrator"
                    ).contains(event.effectiveUser().toLowerCase())
                ) {
                    alerts.add(new Alert(
                        Severity.HIGH,
                        "privileged_interactive_logon",
                        event.timestamp(),
                        event.computer(),
                        event.effectiveUser(),
                        "logonType=" + event.logonType() +
                            ", source=" +
                            event.sourceIp()
                    ));
                }
            }

            return alerts;
        }
    }

    static final class SecurityMonitor {
        private final List<DetectionRule> rules = List.of(
            new FailedLogonRule(),
            new PrivilegeRule(),
            new AccountActivityRule(),
            new PrivilegedLogonRule()
        );

        List<Alert> analyze(List<SecurityEvent> events) {
            List<SecurityEvent> ordered = new ArrayList<>(events);
            ordered.sort(
                java.util.Comparator.comparing(SecurityEvent::timestamp)
            );

            List<Alert> alerts = new ArrayList<>();

            for (DetectionRule rule : rules) {
                alerts.addAll(rule.evaluate(
                    Collections.unmodifiableList(ordered)
                ));
            }

            alerts.sort(
                java.util.Comparator
                    .comparing(Alert::timestamp)
                    .thenComparing(Alert::severity)
            );

            return alerts;
        }
    }

    public static void main(String[] args) {
        try {
            Instant base = Instant.parse("2026-10-20T05:00:00Z");

            List<SecurityEvent> events = List.of(
                new SecurityEvent(
                    4624, base, "WS-01", "SYSTEM", "alice",
                    "10.10.1.20", null, null, 2, null
                ),
                new SecurityEvent(
                    4672, base.plusSeconds(60), "WS-01", "alice",
                    null, null, null, null, null,
                    "SeDebugPrivilege"
                ),
                new SecurityEvent(
                    4688, base.plusSeconds(90), "WS-01", "alice",
                    null, null, "powershell.exe", 2120, null, null
                ),
                new SecurityEvent(
                    4625, base.plusSeconds(120), "WS-01", "scanner",
                    "administrator", "10.10.1.90",
                    null, null, 10, null
                ),
                new SecurityEvent(
                    4625, base.plusSeconds(180), "WS-01", "scanner",
                    "administrator", "10.10.1.90",
                    null, null, 10, null
                ),
                new SecurityEvent(
                    4625, base.plusSeconds(240), "WS-01", "scanner",
                    "administrator", "10.10.1.90",
                    null, null, 10, null
                ),
                new SecurityEvent(
                    4720, base.plusSeconds(300), "DC-01", "admin",
                    "backupsvc", null, null, null, null, null
                ),
                new SecurityEvent(
                    4722, base.plusSeconds(360), "DC-01", "admin",
                    "backupsvc", null, null, null, null, null
                )
            );

            SecurityMonitor monitor = new SecurityMonitor();
            List<Alert> alerts = monitor.analyze(events);

            System.out.println("WINDOWS SECURITY MONITOR");
            System.out.println("========================");
            System.out.println("Events analyzed: " + events.size());

            Map<EventType, Long> counts = new HashMap<>();
            events.forEach(event ->
                counts.merge(event.type(), 1L, Long::sum)
            );

            System.out.println("\nEvent types:");
            counts.forEach((type, count) ->
                System.out.println("  " + type + ": " + count)
            );

            System.out.println("\nAlerts:");
            if (alerts.isEmpty()) {
                System.out.println("  No detection rules triggered.");
            } else {
                alerts.forEach(alert ->
                    System.out.println(
                        "  [" + alert.severity() + "] " +
                        alert.timestamp() + " " +
                        alert.computer() + " " +
                        alert.user() + " " +
                        alert.rule() + ": " +
                        alert.evidence()
                    )
                );
            }
        } catch (RuntimeException exception) {
            System.err.println("ERROR: " + exception.getMessage());
            System.exit(1);
        }
    }
}
