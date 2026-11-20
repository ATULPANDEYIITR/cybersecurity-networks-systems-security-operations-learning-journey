import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

// =========================================================
// SECURITY OPERATIONS FUNDAMENTALS
// Enterprise SOC monitoring and incident management.
// Java 17, standard library only.
// =========================================================

public class SOCOperations {

    // -----------------------------------------------------
    // 1. Enumerations
    // -----------------------------------------------------

    enum Severity {
        LOW(1),
        MEDIUM(2),
        HIGH(3),
        CRITICAL(4);

        private final int level;

        Severity(int level) {
            this.level = level;
        }

        public int level() {
            return level;
        }
    }

    enum Tier {
        L1, L2, L3
    }

    enum IncidentType {
        BRUTE_FORCE,
        MALWARE,
        PHISHING,
        DATA_EXFILTRATION,
        UNAUTHORIZED_ACCESS,
        NETWORK_INTRUSION
    }

    enum IncidentStatus {
        NEW,
        TRIAGED,
        INVESTIGATING,
        ESCALATED,
        CONTAINED,
        RESOLVED,
        CLOSED,
        FALSE_POSITIVE
    }

    // -----------------------------------------------------
    // 2. Domain exceptions
    // -----------------------------------------------------

    static class SOCException extends RuntimeException {
        SOCException(String message) {
            super(message);
        }
    }

    static class ValidationException extends SOCException {
        ValidationException(String message) {
            super(message);
        }
    }

    static class TransitionException extends SOCException {
        TransitionException(String message) {
            super(message);
        }
    }

    static class AssignmentException extends SOCException {
        AssignmentException(String message) {
            super(message);
        }
    }

    // -----------------------------------------------------
    // 3. Security event record
    // -----------------------------------------------------

    record SecurityEvent(
        String id,
        String source,
        String eventType,
        String sourceIp,
        String destination,
        int failedAttempts,
        double transferredMb,
        Instant timestamp
    ) {
        private static final Pattern IPV4 =
            Pattern.compile(
                "^(?:\\d{1,3}\\.){3}\\d{1,3}$"
            );

        SecurityEvent {
            if (id == null || id.isBlank()) {
                throw new ValidationException("Event ID required");
            }

            if (source == null || source.isBlank()) {
                throw new ValidationException("Event source required");
            }

            if (eventType == null || eventType.isBlank()) {
                throw new ValidationException("Event type required");
            }

            if (destination == null || destination.isBlank()) {
                throw new ValidationException("Destination required");
            }

            if (timestamp == null) {
                throw new ValidationException("Timestamp required");
            }

            if (
                sourceIp == null ||
                !IPV4.matcher(sourceIp).matches()
            ) {
                throw new ValidationException("Invalid IPv4 address");
            }

            for (String octet : sourceIp.split("\\.")) {
                int value = Integer.parseInt(octet);

                if (value > 255) {
                    throw new ValidationException(
                        "IPv4 octet outside valid range"
                    );
                }
            }

            if (failedAttempts < 0 || transferredMb < 0) {
                throw new ValidationException(
                    "Negative security measurements"
                );
            }
        }
    }

    // -----------------------------------------------------
    // 4. Analyst domain model
    // -----------------------------------------------------

    record Analyst(
        String id,
        String name,
        Tier tier,
        Set<IncidentType> skills,
        boolean active,
        int maximumAssignments
    ) {
        Analyst {
            if (
                id == null || id.isBlank() ||
                name == null || name.isBlank()
            ) {
                throw new ValidationException(
                    "Analyst identity required"
                );
            }

            if (tier == null || skills == null || skills.isEmpty()) {
                throw new ValidationException(
                    "Analyst tier and skills required"
                );
            }

            if (maximumAssignments < 1) {
                throw new ValidationException(
                    "Invalid assignment capacity"
                );
            }

            skills = Set.copyOf(skills);
        }
    }

    // -----------------------------------------------------
    // 5. Alert and audit models
    // -----------------------------------------------------

    record AuditEntry(
        Instant timestamp,
        String actor,
        String action,
        String details
    ) {}

    static final class Alert {
        private final String id;
        private final SecurityEvent event;
        private final IncidentType type;
        private final Severity severity;
        private final double confidence;

        private IncidentStatus status = IncidentStatus.NEW;
        private Tier assignedTier = Tier.L1;
        private String analystId;

        private final List<String> evidence = new ArrayList<>();
        private final List<AuditEntry> history = new ArrayList<>();

        Alert(
            SecurityEvent event,
            IncidentType type,
            Severity severity,
            double confidence
        ) {
            this.id = UUID.randomUUID().toString();
            this.event = event;
            this.type = type;
            this.severity = severity;
            this.confidence = confidence;

            evidence.add("Automated detection: " + type);

            record(
                "DETECTION_ENGINE",
                "DETECTED",
                "Security rule matched"
            );
        }

        void record(String actor, String action, String details) {
            history.add(new AuditEntry(
                Instant.now(),
                actor,
                action,
                details
            ));
        }

        public String id() {
            return id;
        }

        public SecurityEvent event() {
            return event;
        }

        public IncidentType type() {
            return type;
        }

        public Severity severity() {
            return severity;
        }

        public double confidence() {
            return confidence;
        }

        public IncidentStatus status() {
            return status;
        }

        public Tier assignedTier() {
            return assignedTier;
        }

        public String analystId() {
            return analystId;
        }

        public List<AuditEntry> history() {
            return List.copyOf(history);
        }

        public List<String> evidence() {
            return List.copyOf(evidence);
        }
    }

    // -----------------------------------------------------
    // 6. Detection service
    // -----------------------------------------------------

    interface DetectionService {
        Optional<Alert> analyze(SecurityEvent event);
    }

    static class RuleBasedDetectionService
            implements DetectionService {

        @Override
        public Optional<Alert> analyze(SecurityEvent event) {
            if (event.failedAttempts() >= 25) {
                return Optional.of(new Alert(
                    event,
                    IncidentType.BRUTE_FORCE,
                    Severity.CRITICAL,
                    0.98
                ));
            }

            if (event.failedAttempts() >= 10) {
                return Optional.of(new Alert(
                    event,
                    IncidentType.BRUTE_FORCE,
                    Severity.HIGH,
                    0.90
                ));
            }

            if (event.eventType().equals("malware_detected")) {
                return Optional.of(new Alert(
                    event,
                    IncidentType.MALWARE,
                    Severity.HIGH,
                    0.95
                ));
            }

            if (event.eventType().equals("phishing_report")) {
                return Optional.of(new Alert(
                    event,
                    IncidentType.PHISHING,
                    Severity.MEDIUM,
                    0.85
                ));
            }

            if (event.eventType().equals("unauthorized_access")) {
                return Optional.of(new Alert(
                    event,
                    IncidentType.UNAUTHORIZED_ACCESS,
                    Severity.HIGH,
                    0.90
                ));
            }

            if (
                event.eventType().equals("outbound_transfer") &&
                event.transferredMb() >= 500
            ) {
                return Optional.of(new Alert(
                    event,
                    IncidentType.DATA_EXFILTRATION,
                    Severity.CRITICAL,
                    0.95
                ));
            }

            return Optional.empty();
        }
    }

    // -----------------------------------------------------
    // 7. Analyst assignment service
    // -----------------------------------------------------

    static class AnalystAssignmentService {

        private final Map<String, Analyst> analysts =
            new ConcurrentHashMap<>();

        private final Map<String, AtomicInteger> workload =
            new ConcurrentHashMap<>();

        public void register(Analyst analyst) {
            Analyst existing = analysts.putIfAbsent(
                analyst.id(),
                analyst
            );

            if (existing != null) {
                throw new ValidationException(
                    "Duplicate analyst identity"
                );
            }

            workload.put(
                analyst.id(),
                new AtomicInteger(0)
            );
        }

        public Optional<Analyst> assign(
            IncidentType type,
            Tier minimumTier
        ) {
            List<Analyst> candidates = analysts.values()
                .stream()
                .filter(Analyst::active)
                .filter(a -> a.tier().ordinal() >= minimumTier.ordinal())
                .filter(a -> a.skills().contains(type))
                .sorted(
                    Comparator.comparingInt(
                        a -> a.tier().ordinal()
                    ).thenComparing(Analyst::id)
                )
                .toList();

            for (Analyst analyst : candidates) {
                AtomicInteger count = workload.get(analyst.id());

                while (true) {
                    int current = count.get();

                    if (current >= analyst.maximumAssignments()) {
                        break;
                    }

                    if (count.compareAndSet(current, current + 1)) {
                        return Optional.of(analyst);
                    }
                }
            }

            return Optional.empty();
        }

        public void release(String analystId) {
            AtomicInteger count = workload.get(analystId);

            if (count != null) {
                count.updateAndGet(value -> Math.max(0, value - 1));
            }
        }
    }

    // -----------------------------------------------------
    // 8. Incident policy and state transitions
    // -----------------------------------------------------

    static class IncidentPolicy {

        private static final Map<IncidentStatus, Set<IncidentStatus>>
            TRANSITIONS = Map.of(
                IncidentStatus.NEW,
                Set.of(
                    IncidentStatus.TRIAGED,
                    IncidentStatus.ESCALATED,
                    IncidentStatus.FALSE_POSITIVE
                ),

                IncidentStatus.TRIAGED,
                Set.of(
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.ESCALATED,
                    IncidentStatus.FALSE_POSITIVE
                ),

                IncidentStatus.INVESTIGATING,
                Set.of(
                    IncidentStatus.ESCALATED,
                    IncidentStatus.CONTAINED,
                    IncidentStatus.FALSE_POSITIVE
                ),

                IncidentStatus.ESCALATED,
                Set.of(
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.CONTAINED
                ),

                IncidentStatus.CONTAINED,
                Set.of(IncidentStatus.RESOLVED),

                IncidentStatus.RESOLVED,
                Set.of(IncidentStatus.CLOSED),

                IncidentStatus.FALSE_POSITIVE,
                Set.of(IncidentStatus.CLOSED),

                IncidentStatus.CLOSED,
                Set.of()
            );

        boolean allows(
            IncidentStatus current,
            IncidentStatus next
        ) {
            return TRANSITIONS
                .getOrDefault(current, Set.of())
                .contains(next);
        }
    }

    // -----------------------------------------------------
    // 9. Incident management service
    // -----------------------------------------------------

    static class IncidentManagementService {

        private final AnalystAssignmentService assignmentService;
        private final IncidentPolicy policy = new IncidentPolicy();

        IncidentManagementService(
            AnalystAssignmentService assignmentService
        ) {
            this.assignmentService = assignmentService;
        }

        boolean assign(Alert alert) {
            Tier minimumTier =
                alert.severity.level() >= 4 ? Tier.L3 :
                alert.severity.level() >= 3 ? Tier.L2 :
                Tier.L1;

            Optional<Analyst> result = assignmentService.assign(
                alert.type,
                minimumTier
            );

            if (result.isEmpty()) {
                transition(
                    alert,
                    IncidentStatus.ESCALATED,
                    "SYSTEM",
                    "No qualified analyst available"
                );

                return false;
            }

            Analyst analyst = result.get();

            alert.analystId = analyst.id();
            alert.assignedTier = analyst.tier();

            transition(
                alert,
                IncidentStatus.TRIAGED,
                "SYSTEM",
                "Assigned to " + analyst.name()
            );

            return true;
        }

        void transition(
            Alert alert,
            IncidentStatus next,
            String actor,
            String reason
        ) {
            if (!policy.allows(alert.status, next)) {
                throw new TransitionException(
                    "Invalid incident transition: " +
                    alert.status + " -> " + next
                );
            }

            if (
                actor == null || actor.isBlank() ||
                reason == null || reason.isBlank()
            ) {
                throw new ValidationException(
                    "Actor and reason required"
                );
            }

            if (
                next == IncidentStatus.CONTAINED &&
                alert.evidence.isEmpty()
            ) {
                throw new SOCException(
                    "Containment requires documented evidence"
                );
            }

            alert.status = next;

            alert.record(
                actor,
                next.name(),
                reason
            );

            if (
                next == IncidentStatus.CLOSED ||
                next == IncidentStatus.FALSE_POSITIVE
            ) {
                if (alert.analystId != null) {
                    assignmentService.release(alert.analystId);
                }
            }
        }
    }

    // -----------------------------------------------------
    // 10. SOC event processing
    // -----------------------------------------------------

    static class SOCMonitoringService {

        private final DetectionService detectionService;
        private final IncidentManagementService incidentService;

        private final Map<String, Alert> alerts =
            new ConcurrentHashMap<>();

        private final Set<String> processedEvents =
            ConcurrentHashMap.newKeySet();

        private final int maximumEvents = 10000;

        SOCMonitoringService(
            DetectionService detectionService,
            IncidentManagementService incidentService
        ) {
            this.detectionService = detectionService;
            this.incidentService = incidentService;
        }

        public void process(SecurityEvent event) {
            if (!processedEvents.add(event.id())) {
                throw new ValidationException(
                    "Duplicate event rejected"
                );
            }

            if (alerts.size() >= maximumEvents) {
                processedEvents.remove(event.id());

                throw new SOCException(
                    "SOC processing capacity exceeded"
                );
            }

            Optional<Alert> result =
                detectionService.analyze(event);

            if (result.isEmpty()) {
                System.out.println(
                    "[NORMAL] " + event.id()
                );
                return;
            }

            Alert alert = result.get();

            if (alerts.putIfAbsent(alert.id(), alert) != null) {
                throw new SOCException("Duplicate alert identity");
            }

            incidentService.assign(alert);

            System.out.printf(
                "[ALERT] %s | %s | %s | %s%n",
                alert.id().substring(0, 8),
                alert.type(),
                alert.severity(),
                alert.status()
            );
        }

        public List<Alert> getAlerts() {
            return List.copyOf(alerts.values());
        }
    }

    // -----------------------------------------------------
    // 11. SOC reporting
    // -----------------------------------------------------

    record SOCReport(
        int totalAlerts,
        Map<Severity, Long> severityDistribution,
        Map<IncidentStatus, Long> statusDistribution,
        long activeIncidents,
        long resolvedIncidents,
        long falsePositives
    ) {}

    static class SOCReportingService {

        SOCReport generate(List<Alert> alerts) {

            Map<Severity, Long> severityCounts =
                alerts.stream().collect(
                    Collectors.groupingBy(
                        Alert::severity,
                        () -> new EnumMap<>(Severity.class),
                        Collectors.counting()
                    )
                );

            Map<IncidentStatus, Long> statusCounts =
                alerts.stream().collect(
                    Collectors.groupingBy(
                        Alert::status,
                        () -> new EnumMap<>(IncidentStatus.class),
                        Collectors.counting()
                    )
                );

            long active = alerts.stream()
                .filter(a ->
                    a.status != IncidentStatus.CLOSED &&
                    a.status != IncidentStatus.FALSE_POSITIVE
                )
                .count();

            long resolved = alerts.stream()
                .filter(a ->
                    a.status == IncidentStatus.RESOLVED ||
                    a.status == IncidentStatus.CLOSED
                )
                .count();

            long falsePositives = alerts.stream()
                .filter(a ->
                    a.status == IncidentStatus.FALSE_POSITIVE
                )
                .count();

            return new SOCReport(
                alerts.size(),
                Map.copyOf(severityCounts),
                Map.copyOf(statusCounts),
                active,
                resolved,
                falsePositives
            );
        }
    }

    // -----------------------------------------------------
    // 12. Application entry point
    // -----------------------------------------------------

    public static void main(String[] args) {

        try {
            AnalystAssignmentService analysts =
                new AnalystAssignmentService();

            analysts.register(new Analyst(
                "A001",
                "SOC L1 Analyst",
                Tier.L1,
                Set.of(
                    IncidentType.PHISHING,
                    IncidentType.BRUTE_FORCE
                ),
                true,
                5
            ));

            analysts.register(new Analyst(
                "A002",
                "SOC L2 Responder",
                Tier.L2,
                Set.of(
                    IncidentType.MALWARE,
                    IncidentType.UNAUTHORIZED_ACCESS
                ),
                true,
                5
            ));

            analysts.register(new Analyst(
                "A003",
                "SOC L3 Threat Hunter",
                Tier.L3,
                Set.of(
                    IncidentType.BRUTE_FORCE,
                    IncidentType.DATA_EXFILTRATION
                ),
                true,
                5
            ));

            IncidentManagementService incidentService =
                new IncidentManagementService(analysts);

            SOCMonitoringService monitoring =
                new SOCMonitoringService(
                    new RuleBasedDetectionService(),
                    incidentService
                );

            List<SecurityEvent> events = List.of(
                new SecurityEvent(
                    "EVT-001",
                    "VPN Firewall",
                    "authentication_failure",
                    "203.0.113.45",
                    "VPN Gateway",
                    30,
                    0,
                    Instant.now()
                ),
                new SecurityEvent(
                    "EVT-002",
                    "Endpoint EDR",
                    "malware_detected",
                    "198.51.100.20",
                    "Workstation-17",
                    0,
                    0,
                    Instant.now()
                ),
                new SecurityEvent(
                    "EVT-003",
                    "Email Gateway",
                    "phishing_report",
                    "192.0.2.30",
                    "Mail Server",
                    0,
                    0,
                    Instant.now()
                ),
                new SecurityEvent(
                    "EVT-004",
                    "Firewall",
                    "normal_traffic",
                    "192.0.2.40",
                    "Application Server",
                    0,
                    20,
                    Instant.now()
                )
            );

            for (SecurityEvent event : events) {
                monitoring.process(event);
            }

            // Demonstrate the incident lifecycle.
            Alert firstAlert = monitoring.getAlerts().get(0);

            if (firstAlert.status() == IncidentStatus.TRIAGED) {
                String actor = firstAlert.analystId();

                incidentService.transition(
                    firstAlert,
                    IncidentStatus.INVESTIGATING,
                    actor,
                    "Correlating VPN and identity logs"
                );

                incidentService.transition(
                    firstAlert,
                    IncidentStatus.CONTAINED,
                    actor,
                    "Suspicious source blocked"
                );

                incidentService.transition(
                    firstAlert,
                    IncidentStatus.RESOLVED,
                    actor,
                    "Authentication controls restored"
                );

                incidentService.transition(
                    firstAlert,
                    IncidentStatus.CLOSED,
                    actor,
                    "Evidence archived and documented"
                );
            }

            SOCReport report =
                new SOCReportingService().generate(
                    monitoring.getAlerts()
                );

            System.out.println("\nSOC OPERATIONAL REPORT");
            System.out.println("Total alerts: " + report.totalAlerts());

            System.out.println(
                "Severity distribution: " +
                report.severityDistribution()
            );

            System.out.println(
                "Status distribution: " +
                report.statusDistribution()
            );

            System.out.println(
                "Active incidents: " + report.activeIncidents()
            );

            System.out.println(
                "Resolved incidents: " + report.resolvedIncidents()
            );

            System.out.println(
                "False positives: " + report.falsePositives()
            );

            System.out.println("\nAUDIT HISTORY");

            for (Alert alert : monitoring.getAlerts()) {
                System.out.println(
                    "\nAlert: " + alert.id() +
                    " | " + alert.status()
                );

                alert.history().forEach(entry ->
                    System.out.println(
                        entry.timestamp() + " | " +
                        entry.actor() + " | " +
                        entry.action() + " | " +
                        entry.details()
                    )
                );
            }

            // Duplicate event protection.
            try {
                monitoring.process(events.get(0));
            } catch (SOCException exception) {
                System.out.println(
                    "\nVALIDATION: " + exception.getMessage()
                );
            }

            System.out.println("\nSOC execution completed.");

        } catch (SOCException exception) {
            System.err.println(
                "SOC APPLICATION ERROR: " +
                exception.getMessage()
            );

            System.exit(1);
        }
    }
}
