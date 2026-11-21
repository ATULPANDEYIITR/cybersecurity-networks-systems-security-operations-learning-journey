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
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/*
 * Enterprise SOC Architecture
 *
 * Java 17
 *
 * Models:
 * - Enterprise security data sources
 * - Collection and ingestion
 * - Event normalization
 * - Event storage and indexing
 * - Correlation policies
 * - Security alert lifecycle
 * - Analyst workflows
 * - Operational dashboards
 */

public class SOCArchitecture {

    // --------------------------------------------------------
    // Enumerations
    // --------------------------------------------------------

    enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    enum Category {
        AUTHENTICATION,
        NETWORK,
        ENDPOINT,
        APPLICATION,
        CLOUD
    }

    enum SourceStatus {
        ACTIVE,
        DISABLED,
        DEGRADED
    }

    enum AlertStatus {
        OPEN,
        INVESTIGATING,
        RESOLVED
    }

    enum ReviewOutcome {
        MATCHED,
        NOT_MATCHED
    }

    // --------------------------------------------------------
    // Custom exceptions
    // --------------------------------------------------------

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

    static class CapacityException extends SOCException {
        CapacityException(String message) {
            super(message);
        }
    }

    static class PolicyException extends SOCException {
        PolicyException(String message) {
            super(message);
        }
    }

    // --------------------------------------------------------
    // Immutable domain records
    // --------------------------------------------------------

    record DataSource(
        String id,
        String name,
        String type,
        String environment,
        boolean enabled
    ) {
        DataSource {
            requireText(id, "source ID");
            requireText(name, "source name");
            requireText(type, "source type");
            requireText(environment, "environment");
        }
    }

    record RawEvent(
        String sourceId,
        String payload,
        Instant receivedAt
    ) {
        RawEvent {
            requireText(sourceId, "source ID");
            requireText(payload, "payload");
            Objects.requireNonNull(receivedAt);
        }
    }

    record SecurityEvent(
        String id,
        String sourceId,
        Instant timestamp,
        Category category,
        Severity severity,
        String eventType,
        String sourceIP,
        String destinationIP,
        String username,
        String hostname,
        String message
    ) {
        SecurityEvent {
            requireText(id, "event ID");
            requireText(sourceId, "source ID");
            Objects.requireNonNull(timestamp);
            Objects.requireNonNull(category);
            Objects.requireNonNull(severity);

            requireText(eventType, "event type");

            validateOptionalIP(sourceIP);
            validateOptionalIP(destinationIP);

            validateOptionalLength(username, "username", 255);
            validateOptionalLength(hostname, "hostname", 255);

            message = message == null ? "" : message;
        }
    }

    record CorrelationPolicy(
        String id,
        String title,
        Category category,
        String eventType,
        Severity alertSeverity,
        int threshold,
        Duration window,
        Function<SecurityEvent, String> groupingFunction
    ) {
        CorrelationPolicy {
            requireText(id, "policy ID");
            requireText(title, "policy title");
            Objects.requireNonNull(category);
            requireText(eventType, "event type");
            Objects.requireNonNull(alertSeverity);
            Objects.requireNonNull(window);
            Objects.requireNonNull(groupingFunction);

            if (threshold < 2 || window.isZero() || window.isNegative()) {
                throw new ValidationException(
                    "Invalid correlation policy parameters"
                );
            }
        }
    }

    record AlertEvidence(
        List<String> eventIds,
        Instant firstObserved,
        Instant lastObserved
    ) {
        AlertEvidence {
            eventIds = List.copyOf(eventIds);
            Objects.requireNonNull(firstObserved);
            Objects.requireNonNull(lastObserved);
        }
    }

    // --------------------------------------------------------
    // Mutable alert aggregate
    // --------------------------------------------------------

    static class SecurityAlert {

        private final String id;
        private final String ruleId;
        private final String title;
        private final Severity severity;
        private final AlertEvidence evidence;
        private final String description;
        private final Instant createdAt;

        private AlertStatus status;
        private String assignedAnalyst;

        SecurityAlert(
            String id,
            String ruleId,
            String title,
            Severity severity,
            AlertEvidence evidence,
            String description
        ) {
            this.id = requireText(id, "alert ID");
            this.ruleId = requireText(ruleId, "rule ID");
            this.title = requireText(title, "alert title");
            this.severity = Objects.requireNonNull(severity);
            this.evidence = Objects.requireNonNull(evidence);
            this.description = description;
            this.createdAt = Instant.now();
            this.status = AlertStatus.OPEN;
        }

        void assign(String analyst) {
            assignedAnalyst = requireText(analyst, "analyst");
        }

        void transition(AlertStatus next) {
            Objects.requireNonNull(next);

            boolean valid = switch (status) {
                case OPEN ->
                    next == AlertStatus.INVESTIGATING ||
                    next == AlertStatus.RESOLVED;

                case INVESTIGATING ->
                    next == AlertStatus.OPEN ||
                    next == AlertStatus.RESOLVED;

                case RESOLVED ->
                    next == AlertStatus.OPEN;
            };

            if (!valid) {
                throw new PolicyException(
                    "Invalid alert state transition: " +
                    status + " -> " + next
                );
            }

            status = next;
        }

        String id() {
            return id;
        }

        String ruleId() {
            return ruleId;
        }

        String title() {
            return title;
        }

        Severity severity() {
            return severity;
        }

        AlertStatus status() {
            return status;
        }

        AlertEvidence evidence() {
            return evidence;
        }

        Instant createdAt() {
            return createdAt;
        }

        String assignedAnalyst() {
            return assignedAnalyst;
        }

        String description() {
            return description;
        }
    }

    // --------------------------------------------------------
    // Validation helpers
    // --------------------------------------------------------

    static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ValidationException("Invalid " + field);
        }

        return value.trim();
    }

    static void validateOptionalLength(
        String value,
        String field,
        int maxLength
    ) {
        if (value != null && value.length() > maxLength) {
            throw new ValidationException("Invalid " + field);
        }
    }

    static void validateOptionalIP(String ip) {
        if (ip == null) {
            return;
        }

        String[] parts = ip.split("\\.", -1);

        if (parts.length != 4) {
            throw new ValidationException("Invalid IPv4 address");
        }

        for (String part : parts) {
            if (!part.matches("\\d{1,3}")) {
                throw new ValidationException("Invalid IPv4 address");
            }

            int value = Integer.parseInt(part);

            if (value > 255) {
                throw new ValidationException("Invalid IPv4 address");
            }
        }
    }

    // --------------------------------------------------------
    // Source management
    // --------------------------------------------------------

    static class SourceRegistry {

        private final Map<String, DataSource> sources =
            new HashMap<>();

        void register(DataSource source) {
            if (sources.putIfAbsent(source.id(), source) != null) {
                throw new ValidationException("Duplicate source");
            }
        }

        DataSource get(String sourceId) {
            DataSource source = sources.get(sourceId);

            if (source == null) {
                throw new ValidationException("Unknown source");
            }

            return source;
        }

        List<DataSource> activeSources() {
            return sources.values()
                .stream()
                .filter(DataSource::enabled)
                .toList();
        }
    }

    // --------------------------------------------------------
    // Collection service
    // --------------------------------------------------------

    static class CollectorService {

        private final SourceRegistry registry;
        private final List<RawEvent> buffer = new ArrayList<>();
        private final int capacity;

        private long accepted;
        private long dropped;

        CollectorService(
            SourceRegistry registry,
            int capacity
        ) {
            this.registry = registry;

            if (capacity <= 0) {
                throw new ValidationException("Invalid buffer capacity");
            }

            this.capacity = capacity;
        }

        synchronized boolean collect(
            String sourceId,
            String payload
        ) {
            DataSource source = registry.get(sourceId);

            if (!source.enabled()) {
                dropped++;
                return false;
            }

            requireText(payload, "payload");

            if (payload.getBytes(
                java.nio.charset.StandardCharsets.UTF_8
            ).length > 65536) {
                throw new ValidationException("Payload too large");
            }

            if (buffer.size() >= capacity) {
                dropped++;
                return false;
            }

            buffer.add(
                new RawEvent(sourceId, payload, Instant.now())
            );

            accepted++;
            return true;
        }

        synchronized List<RawEvent> drain(int limit) {
            if (limit <= 0) {
                throw new ValidationException("Invalid batch size");
            }

            int count = Math.min(limit, buffer.size());

            List<RawEvent> batch = new ArrayList<>(
                buffer.subList(0, count)
            );

            buffer.subList(0, count).clear();

            return batch;
        }

        long accepted() {
            return accepted;
        }

        long dropped() {
            return dropped;
        }

        synchronized int pending() {
            return buffer.size();
        }
    }

    // --------------------------------------------------------
    // Event normalization
    // --------------------------------------------------------

    static class EventParser {

        /*
         * Input format:
         *
         * timestamp|category|severity|eventType|sourceIP|
         * destinationIP|username|hostname|message
         *
         * The pipe delimiter is reserved and must not appear
         * unescaped in individual fields.
         */

        SecurityEvent parse(RawEvent raw) {
            String[] fields = raw.payload().split("\\|", -1);

            if (fields.length != 9) {
                throw new ValidationException(
                    "Expected nine event fields"
                );
            }

            try {
                Instant timestamp = Instant.parse(fields[0]);

                Category category = Category.valueOf(
                    fields[1].toUpperCase()
                );

                Severity severity = Severity.valueOf(
                    fields[2].toUpperCase()
                );

                String eventType = requireText(
                    fields[3],
                    "event type"
                );

                String sourceIP = emptyToNull(fields[4]);
                String destinationIP = emptyToNull(fields[5]);
                String username = emptyToNull(fields[6]);
                String hostname = emptyToNull(fields[7]);

                String message = fields[8];

                String eventId = UUID.nameUUIDFromBytes(
                    (raw.sourceId() + "|" + raw.payload())
                        .getBytes(
                            java.nio.charset.StandardCharsets.UTF_8
                        )
                ).toString();

                return new SecurityEvent(
                    eventId,
                    raw.sourceId(),
                    timestamp,
                    category,
                    severity,
                    eventType,
                    sourceIP,
                    destinationIP,
                    username,
                    hostname,
                    message
                );

            } catch (IllegalArgumentException exception) {
                throw new ValidationException(
                    "Event normalization failed: " +
                    exception.getMessage()
                );
            }
        }

        private static String emptyToNull(String value) {
            return value.isBlank() ? null : value;
        }
    }

    // --------------------------------------------------------
    // Event storage and query service
    // --------------------------------------------------------

    static class EventRepository {

        private final Map<String, SecurityEvent> events =
            new HashMap<>();

        private final Map<String, List<String>> userIndex =
            new HashMap<>();

        private final Map<String, List<String>> sourceIndex =
            new HashMap<>();

        private final int maximumCapacity;

        private long duplicates;

        EventRepository(int maximumCapacity) {
            if (maximumCapacity <= 0) {
                throw new ValidationException(
                    "Invalid repository capacity"
                );
            }

            this.maximumCapacity = maximumCapacity;
        }

        synchronized boolean save(SecurityEvent event) {
            if (events.containsKey(event.id())) {
                duplicates++;
                return false;
            }

            if (events.size() >= maximumCapacity) {
                throw new CapacityException(
                    "Event repository is full"
                );
            }

            events.put(event.id(), event);

            if (event.username() != null) {
                userIndex.computeIfAbsent(
                    event.username(),
                    ignored -> new ArrayList<>()
                ).add(event.id());
            }

            sourceIndex.computeIfAbsent(
                event.sourceId(),
                ignored -> new ArrayList<>()
            ).add(event.id());

            return true;
        }

        synchronized List<SecurityEvent> all() {
            return events.values()
                .stream()
                .sorted(Comparator.comparing(
                    SecurityEvent::timestamp
                ))
                .toList();
        }

        synchronized List<SecurityEvent> byUser(String username) {
            return userIndex.getOrDefault(
                username,
                List.of()
            ).stream()
             .map(events::get)
             .filter(Objects::nonNull)
             .toList();
        }

        synchronized List<SecurityEvent> bySource(String sourceId) {
            return sourceIndex.getOrDefault(
                sourceId,
                List.of()
            ).stream()
             .map(events::get)
             .filter(Objects::nonNull)
             .toList();
        }

        synchronized List<SecurityEvent> query(
            Severity severity,
            Category category,
            Instant since
        ) {
            return events.values()
                .stream()
                .filter(event ->
                    severity == null ||
                    event.severity() == severity
                )
                .filter(event ->
                    category == null ||
                    event.category() == category
                )
                .filter(event ->
                    since == null ||
                    !event.timestamp().isBefore(since)
                )
                .sorted(Comparator.comparing(
                    SecurityEvent::timestamp
                ))
                .toList();
        }

        int size() {
            return events.size();
        }

        long duplicates() {
            return duplicates;
        }
    }

    // --------------------------------------------------------
    // Correlation service
    // --------------------------------------------------------

    static class CorrelationService {

        private final List<CorrelationPolicy> policies =
            new ArrayList<>();

        private final Map<String, SecurityAlert> alerts =
            new HashMap<>();

        void registerPolicy(CorrelationPolicy policy) {
            boolean duplicate = policies.stream()
                .anyMatch(existing ->
                    existing.id().equals(policy.id())
                );

            if (duplicate) {
                throw new PolicyException(
                    "Duplicate correlation policy"
                );
            }

            policies.add(policy);
        }

        List<SecurityAlert> evaluate(
            List<SecurityEvent> events
        ) {
            List<SecurityAlert> generated =
                new ArrayList<>();

            for (CorrelationPolicy policy : policies) {
                Map<String, List<SecurityEvent>> groups =
                    events.stream()
                        .filter(event ->
                            event.category() == policy.category()
                        )
                        .filter(event ->
                            event.eventType().equals(policy.eventType())
                        )
                        .filter(event ->
                            event.sourceIP() != null &&
                            event.username() != null
                        )
                        .collect(Collectors.groupingBy(
                            policy.groupingFunction()
                        ));

                for (Map.Entry<
                    String,
                    List<SecurityEvent>
                > entry : groups.entrySet()) {

                    List<SecurityEvent> group = entry.getValue();

                    group.sort(
                        Comparator.comparing(
                            SecurityEvent::timestamp
                        )
                    );

                    int left = 0;

                    for (int right = 0; right < group.size(); right++) {
                        SecurityEvent current = group.get(right);

                        while (
                            left <= right &&
                            Duration.between(
                                group.get(left).timestamp(),
                                current.timestamp()
                            ).compareTo(policy.window()) > 0
                        ) {
                            left++;
                        }

                        List<SecurityEvent> matching =
                            group.subList(left, right + 1);

                        if (matching.size() < policy.threshold()) {
                            continue;
                        }

                        List<String> ids = matching.stream()
                            .map(SecurityEvent::id)
                            .sorted()
                            .toList();

                        String alertId = UUID.nameUUIDFromBytes(
                            (
                                policy.id() + "|" +
                                entry.getKey() + "|" +
                                String.join("|", ids)
                            ).getBytes(
                                java.nio.charset.StandardCharsets.UTF_8
                            )
                        ).toString();

                        if (!alerts.containsKey(alertId)) {
                            AlertEvidence evidence =
                                new AlertEvidence(
                                    ids,
                                    matching.get(0).timestamp(),
                                    current.timestamp()
                                );

                            SecurityAlert alert =
                                new SecurityAlert(
                                    alertId,
                                    policy.id(),
                                    policy.title(),
                                    policy.alertSeverity(),
                                    evidence,
                                    matching.size() +
                                    " matching events for " +
                                    entry.getKey()
                                );

                            alerts.put(alertId, alert);
                            generated.add(alert);
                        }

                        break;
                    }
                }
            }

            // Critical event detection is independent of
            // multi-event threshold correlation.
            for (SecurityEvent event : events) {
                if (event.severity() != Severity.CRITICAL) {
                    continue;
                }

                String id = "CRITICAL-" + event.id();

                if (!alerts.containsKey(id)) {
                    SecurityAlert alert = new SecurityAlert(
                        id,
                        "CRITICAL-EVENT",
                        "Critical security event",
                        Severity.CRITICAL,
                        new AlertEvidence(
                            List.of(event.id()),
                            event.timestamp(),
                            event.timestamp()
                        ),
                        event.message()
                    );

                    alerts.put(id, alert);
                    generated.add(alert);
                }
            }

            return generated;
        }

        SecurityAlert get(String id) {
            SecurityAlert alert = alerts.get(id);

            if (alert == null) {
                throw new ValidationException("Alert not found");
            }

            return alert;
        }

        List<SecurityAlert> all() {
            return List.copyOf(alerts.values());
        }

        long count(AlertStatus status) {
            return alerts.values()
                .stream()
                .filter(alert -> alert.status() == status)
                .count();
        }
    }

    // --------------------------------------------------------
    // Analyst workflow service
    // --------------------------------------------------------

    static class AnalystService {

        private final CorrelationService correlation;

        AnalystService(CorrelationService correlation) {
            this.correlation = correlation;
        }

        void assign(String alertId, String analyst) {
            SecurityAlert alert = correlation.get(alertId);
            alert.assign(analyst);
        }

        void investigate(String alertId) {
            correlation.get(alertId)
                .transition(AlertStatus.INVESTIGATING);
        }

        void resolve(String alertId) {
            SecurityAlert alert = correlation.get(alertId);

            if (alert.assignedAnalyst() == null) {
                throw new PolicyException(
                    "An alert must be assigned before resolution"
                );
            }

            alert.transition(AlertStatus.RESOLVED);
        }
    }

    // --------------------------------------------------------
    // Dashboard service
    // --------------------------------------------------------

    static class DashboardService {

        private final EventRepository repository;
        private final CorrelationService correlation;
        private final CollectorService collector;

        DashboardService(
            EventRepository repository,
            CorrelationService correlation,
            CollectorService collector
        ) {
            this.repository = repository;
            this.correlation = correlation;
            this.collector = collector;
        }

        void print() {
            List<SecurityEvent> events = repository.all();

            Map<Severity, Long> severityCounts =
                new EnumMap<>(Severity.class);

            Map<Category, Long> categoryCounts =
                new EnumMap<>(Category.class);

            for (SecurityEvent event : events) {
                severityCounts.merge(
                    event.severity(),
                    1L,
                    Long::sum
                );

                categoryCounts.merge(
                    event.category(),
                    1L,
                    Long::sum
                );
            }

            System.out.println("\n========== SOC DASHBOARD ==========");
            System.out.println("Total events: " + events.size());

            System.out.println(
                "Total alerts: " + correlation.all().size()
            );

            System.out.println(
                "Open alerts: " +
                correlation.count(AlertStatus.OPEN)
            );

            System.out.println(
                "Investigating alerts: " +
                correlation.count(AlertStatus.INVESTIGATING)
            );

            System.out.println(
                "Resolved alerts: " +
                correlation.count(AlertStatus.RESOLVED)
            );

            System.out.println(
                "Duplicates: " + repository.duplicates()
            );

            System.out.println(
                "Queued events: " + collector.pending()
            );

            System.out.println(
                "Accepted events: " + collector.accepted()
            );

            System.out.println(
                "Dropped events: " + collector.dropped()
            );

            System.out.println("\nSeverity distribution:");

            severityCounts.forEach((key, value) ->
                System.out.println(key + ": " + value)
            );

            System.out.println("\nCategory distribution:");

            categoryCounts.forEach((key, value) ->
                System.out.println(key + ": " + value)
            );

            System.out.println("\nAlert register:");

            for (SecurityAlert alert : correlation.all()) {
                System.out.println(
                    alert.severity() + " | " +
                    alert.title() + " | " +
                    alert.status() + " | " +
                    alert.description()
                );
            }

            System.out.println("===================================");
        }
    }

    // --------------------------------------------------------
    // Enterprise SOC application
    // --------------------------------------------------------

    static class SOCApplication {

        private final SourceRegistry registry =
            new SourceRegistry();

        private final CollectorService collector =
            new CollectorService(registry, 5000);

        private final EventParser parser =
            new EventParser();

        private final EventRepository repository =
            new EventRepository(50000);

        private final CorrelationService correlation =
            new CorrelationService();

        private final AnalystService analysts =
            new AnalystService(correlation);

        private final DashboardService dashboard =
            new DashboardService(
                repository,
                correlation,
                collector
            );

        private long invalidEvents;

        SOCApplication() {
            correlation.registerPolicy(
                new CorrelationPolicy(
                    "AUTH-001",
                    "Possible brute-force attack",
                    Category.AUTHENTICATION,
                    "LOGIN_FAILURE",
                    Severity.HIGH,
                    5,
                    Duration.ofMinutes(5),
                    event ->
                        event.sourceIP() + "|" + event.username()
                )
            );
        }

        SourceRegistry registry() {
            return registry;
        }

        boolean ingest(String sourceId, String payload) {
            return collector.collect(sourceId, payload);
        }

        int processBatch(int limit) {
            int processed = 0;

            for (RawEvent raw : collector.drain(limit)) {
                try {
                    SecurityEvent event = parser.parse(raw);

                    if (repository.save(event)) {
                        processed++;
                    }

                } catch (SOCException exception) {
                    invalidEvents++;

                    System.err.println(
                        "Event rejected: " + exception.getMessage()
                    );
                }
            }

            return processed;
        }

        List<SecurityAlert> analyze() {
            return correlation.evaluate(repository.all());
        }

        void printDashboard() {
            dashboard.print();
        }

        AnalystService analysts() {
            return analysts;
        }

        CorrelationService correlation() {
            return correlation;
        }

        EventRepository repository() {
            return repository;
        }

        long invalidEvents() {
            return invalidEvents;
        }
    }

    // --------------------------------------------------------
    // Demonstration helpers
    // --------------------------------------------------------

    static String payload(
        Instant timestamp,
        String category,
        String severity,
        String eventType,
        String sourceIP,
        String destinationIP,
        String username,
        String hostname,
        String message
    ) {
        return String.join(
            "|",
            timestamp.toString(),
            category,
            severity,
            eventType,
            sourceIP,
            destinationIP,
            username,
            hostname,
            message
        );
    }

    static void verify(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    // --------------------------------------------------------
    // Main
    // --------------------------------------------------------

    public static void main(String[] args) {
        try {
            SOCApplication soc = new SOCApplication();

            soc.registry().register(
                new DataSource(
                    "firewall-01",
                    "Enterprise Firewall",
                    "NETWORK",
                    "PRODUCTION",
                    true
                )
            );

            soc.registry().register(
                new DataSource(
                    "edr-01",
                    "Endpoint Detection",
                    "ENDPOINT",
                    "PRODUCTION",
                    true
                )
            );

            Instant base = Instant.now().minusSeconds(180);

            List<String> payloads = new ArrayList<>();

            for (int i = 0; i < 6; i++) {
                payloads.add(
                    payload(
                        base.plusSeconds(i * 20L),
                        "AUTHENTICATION",
                        "MEDIUM",
                        "LOGIN_FAILURE",
                        "203.0.113.45",
                        "",
                        "admin",
                        "identity-server-01",
                        "Authentication failed"
                    )
                );
            }

            payloads.add(
                payload(
                    Instant.now(),
                    "ENDPOINT",
                    "CRITICAL",
                    "MALWARE_DETECTED",
                    "192.0.2.10",
                    "",
                    "analyst",
                    "endpoint-01",
                    "Suspicious executable detected"
                )
            );

            payloads.add(
                payload(
                    Instant.now(),
                    "NETWORK",
                    "LOW",
                    "CONNECTION_ALLOWED",
                    "192.0.2.20",
                    "198.51.100.10",
                    "",
                    "gateway-01",
                    "Connection permitted"
                )
            );

            for (int i = 0; i < payloads.size(); i++) {
                String source = i == 6
                    ? "edr-01"
                    : "firewall-01";

                verify(
                    soc.ingest(source, payloads.get(i)),
                    "Event ingestion failed"
                );
            }

            int processed = soc.processBatch(100);

            verify(
                processed == payloads.size(),
                "Unexpected processing count"
            );

            List<SecurityAlert> alerts = soc.analyze();

            verify(
                alerts.size() >= 2,
                "Expected alerts were not generated"
            );

            // Duplicate detection.
            soc.ingest("firewall-01", payloads.get(0));
            soc.processBatch(10);

            verify(
                soc.repository().duplicates() == 1,
                "Duplicate handling failed"
            );

            // Invalid event handling.
            soc.ingest("firewall-01", "invalid|payload");
            soc.processBatch(10);

            verify(
                soc.invalidEvents() == 1,
                "Invalid event handling failed"
            );

            // Analyst assignment and investigation.
            SecurityAlert target = soc.correlation()
                .all()
                .stream()
                .filter(alert ->
                    alert.status() == AlertStatus.OPEN
                )
                .findFirst()
                .orElseThrow();

            soc.analysts().assign(target.id(), "analyst-01");
            soc.analysts().investigate(target.id());

            verify(
                target.status() == AlertStatus.INVESTIGATING,
                "Alert investigation transition failed"
            );

            soc.analysts().resolve(target.id());

            verify(
                target.status() == AlertStatus.RESOLVED,
                "Alert resolution failed"
            );

            // Indexed retrieval.
            verify(
                soc.repository().byUser("admin").size() == 6,
                "User index failed"
            );

            soc.printDashboard();

            System.out.println(
                "\nJava 17 enterprise SOC verification passed."
            );

        } catch (Exception exception) {
            System.err.println(
                "SOC application failure: " +
                exception.getMessage()
            );

            exception.printStackTrace();
            System.exit(1);
        }
    }
}
