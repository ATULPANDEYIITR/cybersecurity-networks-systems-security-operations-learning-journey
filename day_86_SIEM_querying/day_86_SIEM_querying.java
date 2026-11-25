import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/*
 * SIEM Enterprise Query and Detection Service
 *
 * Java 17
 *
 * Implements:
 * - Immutable security event records
 * - Validated ingestion
 * - Query policies
 * - Field filtering
 * - Time-window analysis
 * - Aggregation and timelines
 * - Brute-force detection
 * - Reporting and operational controls
 */

public class SIEMQueryEngine {

    enum Severity {
        INFO(0),
        LOW(1),
        MEDIUM(2),
        HIGH(3),
        CRITICAL(4);

        private final int score;

        Severity(int score) {
            this.score = score;
        }

        public int score() {
            return score;
        }
    }

    enum ReviewStatus {
        VALID,
        INVALID,
        QUARANTINED
    }

    record SecurityEvent(
        String eventId,
        Instant timestamp,
        String sourceIp,
        String destinationIp,
        String username,
        String eventType,
        Severity severity,
        String action,
        String source,
        Map<String, String> fields
    ) {
        SecurityEvent {
            requireText(eventId, "eventId");
            Objects.requireNonNull(timestamp, "timestamp");
            requireText(sourceIp, "sourceIp");
            requireText(destinationIp, "destinationIp");
            requireText(username, "username");
            requireText(eventType, "eventType");
            Objects.requireNonNull(severity, "severity");
            requireText(action, "action");
            requireText(source, "source");

            fields = Map.copyOf(
                fields == null ? Map.of() : fields
            );
        }
    }

    record DetectionAlert(
        String sourceIp,
        String username,
        int attempts,
        Instant firstSeen,
        Instant lastSeen,
        Severity severity
    ) {}

    record QueryReport(
        String reportId,
        Instant generatedAt,
        int totalEvents,
        int suspiciousEvents,
        Map<String, Long> severityDistribution,
        Map<String, Long> sourceDistribution,
        Map<Instant, Long> timeline,
        List<DetectionAlert> alerts
    ) {}

    static void requireText(String value, String field) {
        if (value == null ||
            value.isBlank() ||
            value.length() > 512) {
            throw new IllegalArgumentException(
                "Invalid field: " + field
            );
        }
    }

    static class SIEMException extends RuntimeException {
        SIEMException(String message) {
            super(message);
        }
    }

    static class EventRepository {
        private final List<SecurityEvent> events =
            new ArrayList<>();

        private final Set<String> eventIds =
            new HashSet<>();

        private final Map<String, List<SecurityEvent>> sourceIndex =
            new HashMap<>();

        private final Map<String, List<SecurityEvent>> usernameIndex =
            new HashMap<>();

        private final Map<String, List<SecurityEvent>> typeIndex =
            new HashMap<>();

        public synchronized void ingest(SecurityEvent event) {
            Objects.requireNonNull(event);

            if (!eventIds.add(event.eventId())) {
                throw new SIEMException(
                    "Duplicate event ID: " + event.eventId()
                );
            }

            events.add(event);

            sourceIndex.computeIfAbsent(
                event.sourceIp(), key -> new ArrayList<>()
            ).add(event);

            usernameIndex.computeIfAbsent(
                event.username(), key -> new ArrayList<>()
            ).add(event);

            typeIndex.computeIfAbsent(
                event.eventType(), key -> new ArrayList<>()
            ).add(event);
        }

        public synchronized void ingestBatch(
            List<SecurityEvent> batch
        ) {
            Set<String> pending = new HashSet<>();

            for (SecurityEvent event : batch) {
                Objects.requireNonNull(event);

                if (eventIds.contains(event.eventId()) ||
                    !pending.add(event.eventId())) {
                    throw new SIEMException(
                        "Duplicate event in batch"
                    );
                }
            }

            // Validation occurs before the first state mutation.
            batch.forEach(this::ingest);
        }

        public synchronized List<SecurityEvent> snapshot() {
            return List.copyOf(events);
        }

        public synchronized List<SecurityEvent> bySource(
            String sourceIp
        ) {
            return List.copyOf(
                sourceIndex.getOrDefault(sourceIp, List.of())
            );
        }

        public synchronized List<SecurityEvent> byUsername(
            String username
        ) {
            return List.copyOf(
                usernameIndex.getOrDefault(username, List.of())
            );
        }
    }

    static class Query {
        private final List<SecurityEvent> source;
        private final List<Predicate<SecurityEvent>> predicates =
            new ArrayList<>();

        Query(List<SecurityEvent> events) {
            source = List.copyOf(events);
        }

        Query whereSeverity(Set<Severity> allowed) {
            if (allowed == null || allowed.isEmpty()) {
                throw new SIEMException(
                    "Severity filter cannot be empty"
                );
            }

            Set<Severity> immutable = Set.copyOf(allowed);

            predicates.add(
                event -> immutable.contains(event.severity())
            );

            return this;
        }

        Query whereUsername(String username) {
            requireText(username, "username");

            predicates.add(
                event -> event.username().equals(username)
            );

            return this;
        }

        Query whereSourceIp(String ip) {
            requireText(ip, "sourceIp");

            predicates.add(
                event -> event.sourceIp().equals(ip)
            );

            return this;
        }

        Query whereAction(String action) {
            requireText(action, "action");

            predicates.add(
                event -> event.action().equals(action)
            );

            return this;
        }

        Query whereEventType(String eventType) {
            requireText(eventType, "eventType");

            predicates.add(
                event -> event.eventType().equals(eventType)
            );

            return this;
        }

        Query timeRange(Instant start, Instant end) {
            Objects.requireNonNull(start);
            Objects.requireNonNull(end);

            if (start.isAfter(end)) {
                throw new SIEMException("Invalid time range");
            }

            predicates.add(event ->
                !event.timestamp().isBefore(start) &&
                !event.timestamp().isAfter(end)
            );

            return this;
        }

        Query minimumSeverity(Severity minimum) {
            Objects.requireNonNull(minimum);

            predicates.add(
                event -> event.severity().score() >= minimum.score()
            );

            return this;
        }

        List<SecurityEvent> execute() {
            return source.stream()
                .filter(event ->
                    predicates.stream().allMatch(
                        predicate -> predicate.test(event)
                    )
                )
                .sorted(
                    Comparator.comparing(SecurityEvent::timestamp)
                )
                .collect(Collectors.toUnmodifiableList());
        }
    }

    static class AnalyticsService {

        Map<String, Long> aggregate(
            List<SecurityEvent> events,
            String field
        ) {
            return events.stream()
                .map(event -> switch (field) {
                    case "source_ip" -> event.sourceIp();
                    case "destination_ip" -> event.destinationIp();
                    case "username" -> event.username();
                    case "event_type" -> event.eventType();
                    case "severity" -> event.severity().name();
                    case "action" -> event.action();
                    case "source" -> event.source();
                    default -> throw new SIEMException(
                        "Unsupported aggregation field"
                    );
                })
                .collect(Collectors.groupingBy(
                    value -> value,
                    TreeMap::new,
                    Collectors.counting()
                ));
        }

        Map<Severity, Long> severityDistribution(
            List<SecurityEvent> events
        ) {
            Map<Severity, Long> result =
                new EnumMap<>(Severity.class);

            for (Severity severity : Severity.values()) {
                result.put(severity, 0L);
            }

            events.stream()
                .collect(Collectors.groupingBy(
                    SecurityEvent::severity,
                    Collectors.counting()
                ))
                .forEach(result::put);

            return Collections.unmodifiableMap(result);
        }

        Map<Instant, Long> timeline(
            List<SecurityEvent> events,
            Duration interval
        ) {
            if (
                interval == null ||
                interval.isZero() ||
                interval.isNegative()
            ) {
                throw new SIEMException(
                    "Timeline interval must be positive"
                );
            }

            long seconds = interval.getSeconds();

            if (seconds <= 0 || interval.getNano() != 0) {
                throw new SIEMException(
                    "Timeline interval must be whole seconds"
                );
            }

            Map<Instant, Long> buckets = new TreeMap<>();

            for (SecurityEvent event : events) {
                long epoch = event.timestamp().getEpochSecond();

                long bucket = Math.floorDiv(epoch, seconds) * seconds;

                Instant start = Instant.ofEpochSecond(bucket);

                buckets.merge(start, 1L, Long::sum);
            }

            return Collections.unmodifiableMap(buckets);
        }

        Map<String, Map<String, Long>> fieldAnalysis(
            List<SecurityEvent> events
        ) {
            Map<String, Map<String, Long>> result =
                new LinkedHashMap<>();

            for (String field : List.of(
                "source_ip",
                "destination_ip",
                "username",
                "event_type",
                "severity",
                "action",
                "source"
            )) {
                result.put(field, aggregate(events, field));
            }

            return Collections.unmodifiableMap(result);
        }
    }

    static class DetectionService {

        List<DetectionAlert> detectBruteForce(
            List<SecurityEvent> events,
            int threshold,
            Duration window
        ) {
            if (
                threshold < 1 ||
                window == null ||
                window.isZero() ||
                window.isNegative()
            ) {
                throw new SIEMException(
                    "Invalid brute-force detection policy"
                );
            }

            Map<String, List<SecurityEvent>> groups =
                events.stream()
                    .filter(event ->
                        event.eventType().equals("authentication") &&
                        event.action().equals("failure")
                    )
                    .collect(Collectors.groupingBy(
                        event -> event.sourceIp() + "|" +
                                 event.username()
                    ));

            List<DetectionAlert> alerts = new ArrayList<>();

            for (List<SecurityEvent> records : groups.values()) {
                records.sort(
                    Comparator.comparing(SecurityEvent::timestamp)
                );

                int left = 0;

                for (int right = 0; right < records.size(); right++) {
                    while (
                        Duration.between(
                            records.get(left).timestamp(),
                            records.get(right).timestamp()
                        ).compareTo(window) > 0
                    ) {
                        left++;
                    }

                    if (right - left + 1 == threshold) {
                        SecurityEvent first = records.get(left);
                        SecurityEvent last = records.get(right);

                        alerts.add(new DetectionAlert(
                            first.sourceIp(),
                            first.username(),
                            threshold,
                            first.timestamp(),
                            last.timestamp(),
                            Severity.HIGH
                        ));
                    }
                }
            }

            return List.copyOf(alerts);
        }
    }

    static class ReportingService {
        private final AnalyticsService analytics =
            new AnalyticsService();

        private final DetectionService detection =
            new DetectionService();

        QueryReport generate(
            List<SecurityEvent> events
        ) {
            List<SecurityEvent> suspicious =
                new Query(events)
                    .minimumSeverity(Severity.HIGH)
                    .execute();

            return new QueryReport(
                UUID.randomUUID().toString(),
                Instant.now(),
                events.size(),
                suspicious.size(),
                analytics.aggregate(events, "severity"),
                analytics.aggregate(events, "source_ip"),
                analytics.timeline(events, Duration.ofMinutes(5)),
                detection.detectBruteForce(
                    events,
                    5,
                    Duration.ofMinutes(10)
                )
            );
        }
    }

    static List<SecurityEvent> sampleEvents() {
        Instant base = Instant.parse(
            "2026-11-25T02:30:00Z"
        );

        String[][] data = {
            {"E001", "0", "192.168.1.10", "admin", "HIGH", "failure", "authentication"},
            {"E002", "1", "192.168.1.10", "admin", "HIGH", "failure", "authentication"},
            {"E003", "2", "192.168.1.10", "admin", "HIGH", "failure", "authentication"},
            {"E004", "3", "192.168.1.10", "admin", "HIGH", "failure", "authentication"},
            {"E005", "4", "192.168.1.10", "admin", "HIGH", "failure", "authentication"},
            {"E006", "5", "192.168.1.10", "admin", "INFO", "success", "authentication"},
            {"E007", "6", "10.10.1.20", "analyst", "MEDIUM", "blocked", "network"},
            {"E008", "7", "10.10.1.20", "analyst", "CRITICAL", "blocked", "network"},
            {"E009", "8", "172.16.0.25", "service_account", "LOW", "executed", "process"},
            {"E010", "12", "192.168.1.15", "user01", "INFO", "success", "authentication"}
        };

        List<SecurityEvent> events = new ArrayList<>();

        for (String[] row : data) {
            events.add(new SecurityEvent(
                row[0],
                base.plusSeconds(Long.parseLong(row[1]) * 60),
                row[2],
                "10.0.0.5",
                row[3],
                row[6],
                Severity.valueOf(row[4]),
                row[5],
                "security-monitor",
                Map.of()
            ));
        }

        return List.copyOf(events);
    }

    static void runTests(
        EventRepository repository,
        List<SecurityEvent> events
    ) {
        if (repository.snapshot().size() != 10) {
            throw new AssertionError("Ingestion test failed");
        }

        List<SecurityEvent> failed = new Query(events)
            .whereAction("failure")
            .execute();

        if (failed.size() != 5) {
            throw new AssertionError("Action filter failed");
        }

        List<SecurityEvent> high = new Query(events)
            .minimumSeverity(Severity.HIGH)
            .execute();

        if (high.size() != 6) {
            throw new AssertionError("Severity filter failed");
        }

        List<DetectionAlert> alerts =
            new DetectionService().detectBruteForce(
                events,
                5,
                Duration.ofMinutes(10)
            );

        if (alerts.size() != 1) {
            throw new AssertionError("Detection test failed");
        }

        try {
            new Query(events).timeRange(
                Instant.now(),
                Instant.parse("2020-01-01T00:00:00Z")
            );
            throw new AssertionError("Invalid time range accepted");
        } catch (SIEMException expected) {
            // Expected validation result.
        }

        System.out.println("All Java tests passed.");
    }

    static void printMap(
        String title,
        Map<?, ?> values
    ) {
        System.out.println("\n" + title);

        values.forEach(
            (key, value) ->
                System.out.println("  " + key + ": " + value)
        );
    }

    public static void main(String[] args) {
        try {
            EventRepository repository = new EventRepository();

            List<SecurityEvent> events = sampleEvents();

            repository.ingestBatch(events);

            QueryReport report =
                new ReportingService().generate(
                    repository.snapshot()
                );

            System.out.println("=== SIEM ENTERPRISE REPORT ===");
            System.out.println("Report ID: " + report.reportId());
            System.out.println("Total events: " + report.totalEvents());
            System.out.println(
                "Suspicious events: " + report.suspiciousEvents()
            );

            printMap(
                "SEVERITY DISTRIBUTION",
                report.severityDistribution()
            );

            printMap(
                "SOURCE IP DISTRIBUTION",
                report.sourceDistribution()
            );

            printMap(
                "FIVE-MINUTE TIMELINE",
                report.timeline()
            );

            System.out.println("\nBRUTE-FORCE ALERTS");

            report.alerts().forEach(alert ->
                System.out.println(
                    alert.sourceIp() + " -> " +
                    alert.username() +
                    " | attempts=" + alert.attempts() +
                    " | severity=" + alert.severity()
                )
            );

            runTests(repository, events);

        } catch (Exception exception) {
            System.err.println(
                "SIEM processing error: " + exception.getMessage()
            );
            System.exit(1);
        }
    }
}
