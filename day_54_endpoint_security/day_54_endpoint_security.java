import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Enterprise endpoint security case study.
 *
 * Compile: javac EndpointSecurity.java
 * Run: java EndpointSecurity
 *
 * The program processes synthetic endpoint telemetry and does not inspect
 * the host operating system.
 */
public class EndpointSecurity {

    enum SensorType {
        ANTIVIRUS, EDR, HIDS, BEHAVIORAL
    }

    enum Severity {
        LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

        private final int rank;

        Severity(int rank) {
            this.rank = rank;
        }

        int rank() {
            return rank;
        }
    }

    enum IncidentState {
        NEW, TRIAGED, CONTAINED, INVESTIGATING, RESOLVED
    }

    record TelemetryEvent(
            String eventId,
            String endpointId,
            Instant timestamp,
            SensorType sensor,
            String eventType,
            Severity severity,
            String processName,
            String userName,
            String fileHash,
            Map<String, String> details) {

        private static final Pattern IDENTIFIER =
                Pattern.compile("[A-Za-z0-9_.-]{1,128}");
        private static final Pattern SHA256 =
                Pattern.compile("[a-fA-F0-9]{64}");

        TelemetryEvent {
            requireIdentifier(eventId, "eventId");
            requireIdentifier(endpointId, "endpointId");
            requireIdentifier(processName, "processName");
            Objects.requireNonNull(timestamp, "timestamp");
            Objects.requireNonNull(sensor, "sensor");
            Objects.requireNonNull(severity, "severity");
            requireIdentifier(eventType, "eventType");

            if (userName == null || userName.isBlank() || userName.length() > 128) {
                throw new IllegalArgumentException("Invalid user name");
            }
            if (fileHash != null && !SHA256.matcher(fileHash).matches()) {
                throw new IllegalArgumentException("Invalid SHA-256 hash");
            }
            if (details == null || details.size() > 30) {
                throw new IllegalArgumentException("Invalid telemetry details");
            }

            for (Map.Entry<String, String> entry : details.entrySet()) {
                if (entry.getKey().length() > 100 ||
                        entry.getValue() == null ||
                        entry.getValue().length() > 500) {
                    throw new IllegalArgumentException("Telemetry detail exceeds limits");
                }
            }
            details = Map.copyOf(details);
            fileHash = fileHash == null ? null : fileHash.toLowerCase();
        }

        private static void requireIdentifier(String value, String field) {
            if (value == null || !IDENTIFIER.matcher(value).matches()) {
                throw new IllegalArgumentException("Invalid " + field);
            }
        }
    }

    record DetectionRule(
            String name,
            Set<String> eventTypes,
            Set<SensorType> sensors,
            Severity minimumSeverity) {

        DetectionRule {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Rule name is required");
            }
            eventTypes = Set.copyOf(eventTypes);
            sensors = Set.copyOf(sensors);
            Objects.requireNonNull(minimumSeverity);
        }

        boolean matches(TelemetryEvent event) {
            return sensors.contains(event.sensor())
                    && eventTypes.contains(event.eventType());
        }
    }

    record IncidentView(
            String incidentId,
            String endpointId,
            Severity severity,
            IncidentState state,
            List<String> eventIds,
            List<String> reasons) {
    }

    static final class Incident {
        private final String id;
        private final String endpointId;
        private final Severity severity;
        private final Set<String> eventIds;
        private final Set<String> reasons;
        private IncidentState state = IncidentState.NEW;

        Incident(
                String id,
                String endpointId,
                Severity severity,
                Set<String> eventIds,
                Set<String> reasons) {
            this.id = id;
            this.endpointId = endpointId;
            this.severity = severity;
            this.eventIds = new LinkedHashSet<>(eventIds);
            this.reasons = new LinkedHashSet<>(reasons);
        }

        IncidentView view() {
            return new IncidentView(
                    id,
                    endpointId,
                    severity,
                    state,
                    List.copyOf(eventIds),
                    List.copyOf(reasons));
        }
    }

    interface ResponsePolicy {
        boolean shouldContain(IncidentView incident);
    }

    static final class RiskBasedResponsePolicy implements ResponsePolicy {
        private final Severity isolationThreshold;

        RiskBasedResponsePolicy(Severity isolationThreshold) {
            this.isolationThreshold = Objects.requireNonNull(isolationThreshold);
        }

        @Override
        public boolean shouldContain(IncidentView incident) {
            return incident.severity().rank() >= isolationThreshold.rank();
        }
    }

    static final class EndpointSecurityService {
        private final Map<String, TelemetryEvent> telemetry = new HashMap<>();
        private final Map<String, Incident> incidents = new TreeMap<>();
        private final Map<String, String> endpointStates = new TreeMap<>();
        private final List<DetectionRule> rules;
        private final ResponsePolicy responsePolicy;
        private long sequence;

        EndpointSecurityService(ResponsePolicy responsePolicy) {
            this.responsePolicy = Objects.requireNonNull(responsePolicy);
            this.rules = List.of(
                    new DetectionRule(
                            "antivirus-signature",
                            Set.of("malware_detected"),
                            Set.of(SensorType.ANTIVIRUS),
                            Severity.HIGH),
                    new DetectionRule(
                            "antivirus-quarantine",
                            Set.of("quarantine_failed"),
                            Set.of(SensorType.ANTIVIRUS),
                            Severity.HIGH),
                    new DetectionRule(
                            "host-integrity",
                            Set.of("integrity_violation"),
                            Set.of(SensorType.HIDS),
                            Severity.HIGH),
                    new DetectionRule(
                            "suspicious-execution",
                            Set.of("suspicious_process", "credential_access"),
                            Set.of(SensorType.EDR),
                            Severity.MEDIUM));
        }

        void ingest(TelemetryEvent event) {
            Objects.requireNonNull(event);
            TelemetryEvent previous = telemetry.putIfAbsent(event.eventId(), event);

            if (previous != null && !previous.equals(event)) {
                throw new IllegalArgumentException(
                        "Conflicting duplicate event: " + event.eventId());
            }
        }

        List<IncidentView> evaluate() {
            Map<String, List<TelemetryEvent>> byEndpoint = telemetry.values().stream()
                    .collect(Collectors.groupingBy(TelemetryEvent::endpointId));

            List<IncidentView> created = new ArrayList<>();

            for (Map.Entry<String, List<TelemetryEvent>> entry : byEndpoint.entrySet()) {
                List<TelemetryEvent> events = entry.getValue().stream()
                        .sorted(Comparator.comparing(TelemetryEvent::timestamp))
                        .toList();

                Set<String> evidence = new LinkedHashSet<>();
                Set<String> reasons = new LinkedHashSet<>();
                Severity[] severity = {Severity.LOW};

                java.util.function.BiConsumer<TelemetryEvent, String> record =
                        (event, reason) -> {
                            evidence.add(event.eventId());
                            reasons.add(reason);
                            if (event.severity().rank() > severity[0].rank()) {
                                severity[0] = event.severity();
                            }
                        };

                for (TelemetryEvent event : events) {
                    for (DetectionRule rule : rules) {
                        if (rule.matches(event)) {
                            record.accept(event, rule.name());
                            if (rule.minimumSeverity().rank() > severity[0].rank()) {
                                severity[0] = rule.minimumSeverity();
                            }
                        }
                    }

                    if (event.sensor() == SensorType.HIDS &&
                            event.eventType().equals("integrity_violation")) {
                        record.accept(event, "Protected-file integrity violation");
                    }
                }

                List<TelemetryEvent> suspicious = events.stream()
                        .filter(e -> e.sensor() == SensorType.EDR)
                        .filter(e -> e.eventType().equals("suspicious_process")
                                || e.eventType().equals("credential_access"))
                        .toList();

                List<TelemetryEvent> outbound = events.stream()
                        .filter(e -> e.sensor() == SensorType.EDR)
                        .filter(e -> e.eventType().equals("unusual_outbound_connection"))
                        .toList();

                if (!suspicious.isEmpty()) {
                    Instant first = suspicious.stream()
                            .map(TelemetryEvent::timestamp)
                            .min(Comparator.naturalOrder())
                            .orElseThrow();

                    for (TelemetryEvent event : outbound) {
                        long elapsed = Duration.between(first, event.timestamp()).toSeconds();
                        if (elapsed >= 0 && elapsed <= 300) {
                            record.accept(event,
                                    "Suspicious execution correlated with outbound activity");
                            severity[0] = Severity.CRITICAL;
                        }
                    }
                }

                Map<String, Integer> failures = new HashMap<>();
                for (TelemetryEvent event : events) {
                    if (event.sensor() != SensorType.BEHAVIORAL) {
                        continue;
                    }

                    if (event.eventType().equals("authentication_failure")) {
                        failures.merge(event.userName(), 1, Integer::sum);
                    } else if (event.eventType().equals("authentication_success")
                            && failures.getOrDefault(event.userName(), 0) >= 5) {
                        record.accept(event,
                                "Repeated authentication failures followed by success");
                        if (severity[0].rank() < Severity.HIGH.rank()) {
                            severity[0] = Severity.HIGH;
                        }
                    }
                }

                if (evidence.isEmpty()) {
                    continue;
                }

                String id = "INC-" + String.format("%05d", ++sequence);
                Incident incident = new Incident(
                        id, entry.getKey(), severity[0], evidence, reasons);
                incidents.put(id, incident);
                IncidentView view = incident.view();
                created.add(view);

                if (responsePolicy.shouldContain(view)) {
                    transition(id, IncidentState.TRIAGED);
                    transition(id, IncidentState.CONTAINED);
                }
            }

            return List.copyOf(created);
        }

        void transition(String incidentId, IncidentState next) {
            Incident incident = incidents.get(incidentId);
            if (incident == null) {
                throw new IllegalArgumentException("Unknown incident: " + incidentId);
            }

            Map<IncidentState, Set<IncidentState>> allowed = Map.of(
                    IncidentState.NEW, Set.of(IncidentState.TRIAGED),
                    IncidentState.TRIAGED,
                    Set.of(IncidentState.CONTAINED, IncidentState.INVESTIGATING),
                    IncidentState.CONTAINED, Set.of(IncidentState.INVESTIGATING),
                    IncidentState.INVESTIGATING,
                    Set.of(IncidentState.CONTAINED, IncidentState.RESOLVED),
                    IncidentState.RESOLVED, Set.of());

            if (!allowed.get(incident.state).contains(next)) {
                throw new IllegalStateException(
                        "Invalid transition " + incident.state + " -> " + next);
            }

            incident.state = next;
            if (next == IncidentState.CONTAINED) {
                endpointStates.put(incident.endpointId, "isolated");
            } else if (next == IncidentState.RESOLVED) {
                endpointStates.put(incident.endpointId, "review_required");
            }
        }

        void printReport() {
            Map<Severity, Long> bySeverity = incidents.values().stream()
                    .collect(Collectors.groupingBy(
                            i -> i.severity,
                            () -> new EnumMap<>(Severity.class),
                            Collectors.counting()));

            System.out.println("Endpoint security report");
            System.out.println("========================");
            System.out.println("Telemetry events: " + telemetry.size());
            System.out.println("Incidents: " + incidents.size());
            System.out.println("Incident counts by severity: " + bySeverity);
            System.out.println("Endpoint states: " + endpointStates);

            incidents.values().forEach(incident -> {
                IncidentView view = incident.view();
                System.out.printf(
                        "%s endpoint=%s severity=%s state=%s evidence=%d%n",
                        view.incidentId(),
                        view.endpointId(),
                        view.severity(),
                        view.state(),
                        view.eventIds().size());
                view.reasons().forEach(reason -> System.out.println("  - " + reason));
            });
        }

        Map<String, IncidentView> snapshot() {
            return incidents.values().stream().collect(Collectors.toUnmodifiableMap(
                    incident -> incident.id,
                    Incident::view));
        }
    }

    private static TelemetryEvent event(
            String id,
            String endpoint,
            long offsetSeconds,
            SensorType sensor,
            String type,
            Severity severity,
            String process,
            String user) {
        return new TelemetryEvent(
                id,
                endpoint,
                Instant.parse("2026-10-24T04:00:00Z").plusSeconds(offsetSeconds),
                sensor,
                type,
                severity,
                process,
                user,
                null,
                Map.of());
    }

    public static void main(String[] args) {
        EndpointSecurityService service = new EndpointSecurityService(
                new RiskBasedResponsePolicy(Severity.CRITICAL));

        List<TelemetryEvent> events = new ArrayList<>(List.of(
                event("EV-001", "WS-101", 0, SensorType.ANTIVIRUS,
                        "malware_detected", Severity.HIGH, "invoice.exe", "employee"),
                event("EV-002", "WS-202", 1, SensorType.HIDS,
                        "integrity_violation", Severity.HIGH, "sshd", "root"),
                event("EV-003", "WS-303", 2, SensorType.EDR,
                        "suspicious_process", Severity.HIGH, "powershell.exe", "employee"),
                event("EV-004", "WS-303", 30, SensorType.EDR,
                        "unusual_outbound_connection", Severity.MEDIUM,
                        "powershell.exe", "employee")
        ));

        for (int i = 1; i <= 5; i++) {
            events.add(event("AUTH-" + i, "WS-404", i,
                    SensorType.BEHAVIORAL, "authentication_failure",
                    Severity.MEDIUM, "login_service", "svc-backup"));
        }
        events.add(event("AUTH-6", "WS-404", 10,
                SensorType.BEHAVIORAL, "authentication_success",
                Severity.MEDIUM, "login_service", "svc-backup"));

        events.forEach(service::ingest);
        service.ingest(events.getFirst());

        List<IncidentView> incidents = service.evaluate();
        service.printReport();

        if (incidents.stream().noneMatch(
                i -> i.severity() == Severity.CRITICAL)) {
            throw new IllegalStateException("Expected a critical correlated incident");
        }

        try {
            service.transition("UNKNOWN", IncidentState.RESOLVED);
            throw new IllegalStateException("Unknown incident was accepted");
        } catch (IllegalArgumentException expected) {
            System.out.println("Unknown incident validation passed.");
        }

        try {
            new TelemetryEvent(
                    "INVALID ID",
                    "WS-101",
                    Instant.now(),
                    SensorType.EDR,
                    "process_started",
                    Severity.LOW,
                    "explorer.exe",
                    "employee",
                    null,
                    Map.of());
            throw new IllegalStateException("Invalid identifier was accepted");
        } catch (IllegalArgumentException expected) {
            System.out.println("Telemetry validation passed.");
        }
    }
}
