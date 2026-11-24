import java.time.Duration;
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
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;

/*
 * SIEM FUNDAMENTALS
 *
 * Enterprise-oriented SIEM implementation.
 *
 * Java 17
 * No external dependencies.
 *
 * Compile:
 * javac SIEMEnterprise.java
 *
 * Run:
 * java SIEMEnterprise
 */

public class SIEMEnterprise {

    enum Severity {
        INFO, LOW, MEDIUM, HIGH, CRITICAL
    }

    enum Category {
        AUTHENTICATION,
        NETWORK,
        ENDPOINT,
        FIREWALL,
        DNS,
        APPLICATION
    }

    enum AlertStatus {
        NEW,
        ACKNOWLEDGED,
        INVESTIGATING,
        RESOLVED,
        FALSE_POSITIVE
    }

    enum ReviewOutcome {
        MATCH,
        NO_MATCH
    }

    record SecurityEvent(
        String eventId,
        Instant timestamp,
        String source,
        Category category,
        String eventType,
        Severity severity,
        Map<String, String> fields
    ) {
        SecurityEvent {
            Objects.requireNonNull(eventId);
            Objects.requireNonNull(timestamp);
            Objects.requireNonNull(category);
            Objects.requireNonNull(severity);
            Objects.requireNonNull(fields);

            if (eventId.isBlank() || eventId.length() > 128) {
                throw new IllegalArgumentException("Invalid event ID");
            }

            if (source == null || source.isBlank() || source.length() > 100) {
                throw new IllegalArgumentException("Invalid source");
            }

            if (
                eventType == null ||
                !eventType.matches("[A-Za-z0-9_.-]{1,100}")
            ) {
                throw new IllegalArgumentException("Invalid event type");
            }

            if (fields.size() > 100) {
                throw new IllegalArgumentException("Too many event fields");
            }

            Map<String, String> copy = new HashMap<>();

            for (var entry : fields.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                if (
                    key == null ||
                    key.isBlank() ||
                    key.length() > 100 ||
                    value == null ||
                    value.length() > 4096
                ) {
                    throw new IllegalArgumentException(
                        "Invalid event field"
                    );
                }

                copy.put(key, value);
            }

            fields = Map.copyOf(copy);
        }

        String fieldValue(String field) {
            return switch (field) {
                case "event_id" -> eventId;
                case "source" -> source;
                case "category" -> category.name();
                case "event_type" -> eventType;
                case "severity" -> severity.name();
                case "timestamp" -> timestamp.toString();
                default -> fields.get(field);
            };
        }
    }


    record SearchCriteria(
        String field,
        String value,
        Category category,
        Severity severity,
        Instant startTime,
        Instant endTime,
        int limit
    ) {
        SearchCriteria {
            if (limit < 1 || limit > 10000) {
                throw new IllegalArgumentException("Invalid search limit");
            }

            if (
                startTime != null &&
                endTime != null &&
                startTime.isAfter(endTime)
            ) {
                throw new IllegalArgumentException("Invalid time range");
            }
        }
    }


    record SearchResult(
        List<SecurityEvent> events,
        int total,
        long executionNanos
    ) {
        SearchResult {
            events = List.copyOf(events);
        }
    }


    record CorrelationRule(
        String ruleId,
        String name,
        String eventType,
        String groupField,
        Duration window,
        int threshold,
        Severity severity
    ) {
        CorrelationRule {
            if (
                ruleId == null ||
                ruleId.isBlank() ||
                name == null ||
                name.isBlank()
            ) {
                throw new IllegalArgumentException(
                    "Rule identity is required"
                );
            }

            Objects.requireNonNull(window);
            Objects.requireNonNull(severity);

            if (
                window.isZero() ||
                window.isNegative() ||
                threshold < 1
            ) {
                throw new IllegalArgumentException(
                    "Invalid correlation rule parameters"
                );
            }
        }
    }


    static final class Alert {
        private final String alertId;
        private final String ruleId;
        private final String title;
        private final Severity severity;
        private final Instant createdAt;
        private final List<String> eventIds;
        private final String description;

        private AlertStatus status;
        private String assignedTo;

        Alert(
            String alertId,
            String ruleId,
            String title,
            Severity severity,
            Instant createdAt,
            List<String> eventIds,
            String description
        ) {
            this.alertId = alertId;
            this.ruleId = ruleId;
            this.title = title;
            this.severity = severity;
            this.createdAt = createdAt;
            this.eventIds = List.copyOf(eventIds);
            this.description = description;
            this.status = AlertStatus.NEW;
            this.assignedTo = null;
        }

        synchronized void transition(
            AlertStatus next,
            String analyst
        ) {
            Map<AlertStatus, Set<AlertStatus>> transitions =
                Map.of(
                    AlertStatus.NEW,
                    Set.of(
                        AlertStatus.ACKNOWLEDGED,
                        AlertStatus.FALSE_POSITIVE
                    ),
                    AlertStatus.ACKNOWLEDGED,
                    Set.of(
                        AlertStatus.INVESTIGATING,
                        AlertStatus.RESOLVED,
                        AlertStatus.FALSE_POSITIVE
                    ),
                    AlertStatus.INVESTIGATING,
                    Set.of(
                        AlertStatus.RESOLVED,
                        AlertStatus.FALSE_POSITIVE
                    ),
                    AlertStatus.RESOLVED,
                    Set.of(),
                    AlertStatus.FALSE_POSITIVE,
                    Set.of()
                );

            if (!transitions.get(status).contains(next)) {
                throw new IllegalStateException(
                    "Invalid alert state transition"
                );
            }

            if (analyst != null) {
                if (analyst.isBlank() || analyst.length() > 100) {
                    throw new IllegalArgumentException(
                        "Invalid analyst identity"
                    );
                }

                assignedTo = analyst;
            }

            status = next;
        }

        String alertId() {
            return alertId;
        }

        AlertStatus status() {
            return status;
        }

        Severity severity() {
            return severity;
        }

        String title() {
            return title;
        }

        List<String> eventIds() {
            return eventIds;
        }

        String assignedTo() {
            return assignedTo;
        }

        @Override
        public String toString() {
            return "Alert{" +
                "id='" + alertId + '\'' +
                ", rule='" + ruleId + '\'' +
                ", title='" + title + '\'' +
                ", severity=" + severity +
                ", status=" + status +
                ", events=" + eventIds.size() +
                '}';
        }
    }


    static final class SIEMException extends RuntimeException {
        SIEMException(String message) {
            super(message);
        }
    }


    static final class EventRepository {

        private final Map<String, SecurityEvent> events =
            new ConcurrentHashMap<>();

        // field -> normalized value -> event IDs
        private final Map<
            String,
            Map<String, Set<String>>
        > indexes = new ConcurrentHashMap<>();

        private final LongAdder accepted = new LongAdder();
        private final LongAdder duplicates = new LongAdder();

        private static String normalize(String value) {
            return value.toLowerCase().trim();
        }

        boolean ingest(SecurityEvent event) {
            Objects.requireNonNull(event);

            SecurityEvent previous = events.putIfAbsent(
                event.eventId(),
                event
            );

            if (previous != null) {
                duplicates.increment();
                return false;
            }

            Map<String, String> values = new HashMap<>(
                event.fields()
            );

            values.put("source", event.source());
            values.put("category", event.category().name());
            values.put("severity", event.severity().name());
            values.put("event_type", event.eventType());

            for (var entry : values.entrySet()) {
                String field = entry.getKey();
                String value = normalize(entry.getValue());

                indexes.computeIfAbsent(
                    field,
                    ignored -> new ConcurrentHashMap<>()
                ).computeIfAbsent(
                    value,
                    ignored -> ConcurrentHashMap.newKeySet()
                ).add(event.eventId());
            }

            accepted.increment();

            return true;
        }

        SearchResult search(SearchCriteria criteria) {
            long started = System.nanoTime();

            Set<String> candidates = null;

            if (
                criteria.field() != null &&
                criteria.value() != null
            ) {
                candidates = new HashSet<>(
                    indexes.getOrDefault(
                        criteria.field(),
                        Map.of()
                    ).getOrDefault(
                        normalize(criteria.value()),
                        Set.of()
                    )
                );
            }

            if (criteria.category() != null) {
                candidates = intersect(
                    candidates,
                    indexes.getOrDefault("category", Map.of())
                        .getOrDefault(
                            criteria.category().name().toLowerCase(),
                            Set.of()
                        )
                );
            }

            if (criteria.severity() != null) {
                candidates = intersect(
                    candidates,
                    indexes.getOrDefault("severity", Map.of())
                        .getOrDefault(
                            criteria.severity().name().toLowerCase(),
                            Set.of()
                        )
                );
            }

            if (candidates == null) {
                candidates = new HashSet<>(events.keySet());
            }

            List<SecurityEvent> matches = candidates.stream()
                .map(events::get)
                .filter(Objects::nonNull)
                .filter(event -> {
                    if (
                        criteria.startTime() != null &&
                        event.timestamp().isBefore(criteria.startTime())
                    ) {
                        return false;
                    }

                    if (
                        criteria.endTime() != null &&
                        event.timestamp().isAfter(criteria.endTime())
                    ) {
                        return false;
                    }

                    if (
                        criteria.field() != null &&
                        criteria.value() != null
                    ) {
                        String actual = event.fieldValue(criteria.field());

                        return actual != null &&
                            normalize(actual).equals(
                                normalize(criteria.value())
                            );
                    }

                    return true;
                })
                .sorted(
                    Comparator.comparing(
                        SecurityEvent::timestamp
                    ).reversed().thenComparing(
                        SecurityEvent::eventId
                    )
                )
                .collect(Collectors.toCollection(ArrayList::new));

            int total = matches.size();

            List<SecurityEvent> limited = matches.stream()
                .limit(criteria.limit())
                .toList();

            return new SearchResult(
                limited,
                total,
                System.nanoTime() - started
            );
        }

        private Set<String> intersect(
            Set<String> first,
            Set<String> second
        ) {
            if (first == null) {
                return new HashSet<>(second);
            }

            first.retainAll(second);
            return first;
        }

        long eventCount() {
            return events.size();
        }

        long duplicateCount() {
            return duplicates.sum();
        }

        long acceptedCount() {
            return accepted.sum();
        }

        Map<String, Long> severityDistribution() {
            return events.values().stream().collect(
                Collectors.groupingBy(
                    event -> event.severity().name(),
                    TreeMap::new,
                    Collectors.counting()
                )
            );
        }

        Map<String, Long> categoryDistribution() {
            return events.values().stream().collect(
                Collectors.groupingBy(
                    event -> event.category().name(),
                    TreeMap::new,
                    Collectors.counting()
                )
            );
        }
    }


    static final class CorrelationService {

        private final EventRepository repository;

        private final Map<String, CorrelationRule> rules =
            new ConcurrentHashMap<>();

        private final Map<String, Alert> alerts =
            new ConcurrentHashMap<>();

        private final Set<String> processed =
            ConcurrentHashMap.newKeySet();

        CorrelationService(EventRepository repository) {
            this.repository = repository;
        }

        void register(CorrelationRule rule) {
            if (rules.putIfAbsent(rule.ruleId(), rule) != null) {
                throw new SIEMException("Duplicate rule");
            }
        }

        List<Alert> evaluate(Instant now) {
            List<Alert> generated = new ArrayList<>();

            for (CorrelationRule rule : rules.values()) {
                Instant start = now.minus(rule.window());

                SearchCriteria criteria = new SearchCriteria(
                    "event_type",
                    rule.eventType(),
                    null,
                    null,
                    start,
                    now,
                    10000
                );

                SearchResult result = repository.search(criteria);

                Map<String, List<SecurityEvent>> groups =
                    result.events().stream().collect(
                        Collectors.groupingBy(
                            event -> event.fieldValue(
                                rule.groupField()
                            ),
                            HashMap::new,
                            Collectors.toList()
                        )
                    );

                long bucket = now.getEpochSecond() /
                    rule.window().toSeconds();

                for (var entry : groups.entrySet()) {
                    String groupKey = entry.getKey();
                    List<SecurityEvent> events = entry.getValue();

                    if (
                        groupKey == null ||
                        events.size() < rule.threshold()
                    ) {
                        continue;
                    }

                    String fingerprint = rule.ruleId() +
                        "|" + groupKey +
                        "|" + bucket;

                    if (!processed.add(fingerprint)) {
                        continue;
                    }

                    List<String> eventIds = events.stream()
                        .map(SecurityEvent::eventId)
                        .sorted()
                        .toList();

                    String alertId = UUID.nameUUIDFromBytes(
                        fingerprint.getBytes(
                            java.nio.charset.StandardCharsets.UTF_8
                        )
                    ).toString();

                    Alert alert = new Alert(
                        alertId,
                        rule.ruleId(),
                        rule.name(),
                        rule.severity(),
                        now,
                        eventIds,
                        events.size() +
                            " matching events for " +
                            rule.groupField() + "=" + groupKey
                    );

                    alerts.put(alertId, alert);
                    generated.add(alert);
                }
            }

            return generated;
        }

        Alert transition(
            String alertId,
            AlertStatus next,
            String analyst
        ) {
            Alert alert = alerts.get(alertId);

            if (alert == null) {
                throw new SIEMException("Alert not found");
            }

            alert.transition(next, analyst);
            return alert;
        }

        List<Alert> getAlerts() {
            return List.copyOf(alerts.values());
        }
    }


    static final class SIEMApplication {

        private final EventRepository repository =
            new EventRepository();

        private final CorrelationService correlation =
            new CorrelationService(repository);

        void run() {
            Instant base = Instant.parse(
                "2026-11-24T06:00:00Z"
            );

            for (int i = 1; i <= 6; i++) {
                SecurityEvent event = new SecurityEvent(
                    "AUTH-" + i,
                    base.plusSeconds(i * 5L),
                    "linux-auth-01",
                    Category.AUTHENTICATION,
                    "failed_login",
                    Severity.MEDIUM,
                    Map.of(
                        "src_ip", "203.0.113.45",
                        "username", "admin",
                        "host", "server-01",
                        "protocol", "ssh",
                        "result", "failure"
                    )
                );

                repository.ingest(event);
            }

            SecurityEvent firewall = new SecurityEvent(
                "FW-001",
                base.plusSeconds(30),
                "firewall-01",
                Category.FIREWALL,
                "blocked_connection",
                Severity.HIGH,
                Map.of(
                    "src_ip", "203.0.113.45",
                    "dst_port", "22",
                    "action", "blocked"
                )
            );

            repository.ingest(firewall);

            // A duplicate identifier must not overwrite an event.
            if (repository.ingest(firewall)) {
                throw new SIEMException("Deduplication failure");
            }

            correlation.register(
                new CorrelationRule(
                    "RULE-001",
                    "SSH Brute Force",
                    "failed_login",
                    "src_ip",
                    Duration.ofMinutes(5),
                    5,
                    Severity.CRITICAL
                )
            );

            System.out.println("=== SEARCH ===");

            SearchResult result = repository.search(
                new SearchCriteria(
                    "src_ip",
                    "203.0.113.45",
                    Category.AUTHENTICATION,
                    null,
                    base.minusSeconds(60),
                    base.plusSeconds(300),
                    100
                )
            );

            System.out.println("Matches: " + result.total());

            System.out.printf(
                "Execution: %.3f ms%n",
                result.executionNanos() / 1_000_000.0
            );

            result.events().forEach(event ->
                System.out.println(
                    event.eventId() + " | " +
                    event.eventType() + " | " +
                    event.fieldValue("src_ip")
                )
            );

            System.out.println("\n=== CORRELATION ===");

            List<Alert> generated = correlation.evaluate(
                base.plusSeconds(60)
            );

            generated.forEach(System.out::println);

            for (Alert alert : generated) {
                correlation.transition(
                    alert.alertId(),
                    AlertStatus.ACKNOWLEDGED,
                    "soc-analyst-01"
                );

                correlation.transition(
                    alert.alertId(),
                    AlertStatus.INVESTIGATING,
                    null
                );

                if (alert.status() != AlertStatus.INVESTIGATING) {
                    throw new SIEMException(
                        "Alert workflow test failed"
                    );
                }
            }

            if (!correlation.evaluate(base.plusSeconds(60)).isEmpty()) {
                throw new SIEMException(
                    "Duplicate correlation alert detected"
                );
            }

            System.out.println("\n=== REPORTING ===");

            System.out.println(
                "Events: " + repository.eventCount()
            );

            System.out.println(
                "Accepted: " + repository.acceptedCount()
            );

            System.out.println(
                "Duplicates: " + repository.duplicateCount()
            );

            System.out.println(
                "Categories: " + repository.categoryDistribution()
            );

            System.out.println(
                "Severities: " + repository.severityDistribution()
            );

            System.out.println(
                "Alerts: " + correlation.getAlerts().size()
            );
        }
    }


    public static void main(String[] args) {
        try {
            new SIEMApplication().run();

            System.out.println("\nSIEM enterprise tests passed.");
        } catch (RuntimeException exception) {
            System.err.println(
                "SIEM ERROR: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
