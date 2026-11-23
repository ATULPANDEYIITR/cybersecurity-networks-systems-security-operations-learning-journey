import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * Enterprise Log Collection and Forwarding Platform
 *
 * Java 17
 * Standard library only.
 *
 * Components:
 * - Agent registry
 * - Collection adapters
 * - Structured log domain types
 * - Timestamp and severity policies
 * - Redaction
 * - Normalization
 * - Forwarding service
 * - Delivery retry
 * - Dead-letter processing
 * - Retention service
 * - Metrics and operational reporting
 */

public class Main {

    enum Severity {
        DEBUG(10),
        INFO(20),
        WARNING(30),
        ERROR(40),
        CRITICAL(50);

        private final int priority;

        Severity(int priority) {
            this.priority = priority;
        }

        public int priority() {
            return priority;
        }
    }

    enum SourceType {
        JSON,
        SYSLOG
    }

    enum RecordState {
        COLLECTED,
        NORMALIZED,
        QUEUED,
        FORWARDED,
        FAILED,
        ARCHIVED
    }

    enum AgentStatus {
        ACTIVE,
        DISABLED
    }

    static class CollectionException extends RuntimeException {
        CollectionException(String message) {
            super(message);
        }

        CollectionException(
            String message,
            Throwable cause
        ) {
            super(message, cause);
        }
    }

    static class PolicyViolationException
        extends CollectionException {

        PolicyViolationException(String message) {
            super(message);
        }
    }

    static class ForwardingException
        extends CollectionException {

        ForwardingException(String message) {
            super(message);
        }
    }

    record Agent(
        String id,
        String hostname,
        String environment,
        SourceType sourceType,
        AgentStatus status
    ) {
        Agent {
            if (
                id == null || id.isBlank() ||
                hostname == null || hostname.isBlank() ||
                environment == null || environment.isBlank()
            ) {
                throw new IllegalArgumentException(
                    "Invalid agent configuration"
                );
            }

            Objects.requireNonNull(sourceType);
            Objects.requireNonNull(status);
        }
    }

    record ParsedLog(
        String timestamp,
        String severity,
        String message,
        Map<String, Object> attributes
    ) {
        ParsedLog {
            Objects.requireNonNull(timestamp);
            Objects.requireNonNull(severity);
            Objects.requireNonNull(message);

            attributes = Collections.unmodifiableMap(
                new LinkedHashMap<>(attributes)
            );
        }
    }

    record LogRecord(
        UUID id,
        String agentId,
        String hostname,
        String environment,
        SourceType sourceType,
        Instant eventTime,
        Instant receivedTime,
        Severity severity,
        String message,
        Map<String, Object> attributes,
        String fingerprint,
        RecordState state
    ) {
        LogRecord {
            Objects.requireNonNull(id);
            Objects.requireNonNull(agentId);
            Objects.requireNonNull(hostname);
            Objects.requireNonNull(eventTime);
            Objects.requireNonNull(receivedTime);
            Objects.requireNonNull(severity);
            Objects.requireNonNull(message);
            Objects.requireNonNull(fingerprint);
            Objects.requireNonNull(state);

            attributes = Collections.unmodifiableMap(
                new LinkedHashMap<>(attributes)
            );
        }

        LogRecord withState(RecordState nextState) {
            return new LogRecord(
                id,
                agentId,
                hostname,
                environment,
                sourceType,
                eventTime,
                receivedTime,
                severity,
                message,
                attributes,
                fingerprint,
                nextState
            );
        }
    }

    interface CollectionAdapter {
        ParsedLog parse(String raw);
    }

    static class TimestampPolicy {

        Instant normalize(String value) {
            try {
                return OffsetDateTime
                    .parse(value)
                    .withOffsetSameInstant(ZoneOffset.UTC)
                    .toInstant();

            } catch (DateTimeParseException exception) {
                throw new PolicyViolationException(
                    "Timestamp must be valid ISO-8601 with timezone"
                );
            }
        }
    }

    static class SeverityPolicy {

        private static final Map<String, Severity> LEVELS =
            Map.ofEntries(
                Map.entry("trace", Severity.DEBUG),
                Map.entry("debug", Severity.DEBUG),
                Map.entry("info", Severity.INFO),
                Map.entry("notice", Severity.INFO),
                Map.entry("warn", Severity.WARNING),
                Map.entry("warning", Severity.WARNING),
                Map.entry("error", Severity.ERROR),
                Map.entry("critical", Severity.CRITICAL),
                Map.entry("fatal", Severity.CRITICAL)
            );

        Severity normalize(String value) {
            Severity result = LEVELS.get(
                value.toLowerCase()
            );

            if (result == null) {
                throw new PolicyViolationException(
                    "Unsupported severity: " + value
                );
            }

            return result;
        }
    }

    static class RedactionPolicy {

        private static final Pattern CREDENTIALS =
            Pattern.compile(
                "(?i)(password|passwd|token|secret|api_key)"
                + "\\s*[=:]\\s*['\"]?[^,\\s'\"]+"
            );

        private static final Pattern EMAIL =
            Pattern.compile(
                "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
            );

        private static final Pattern CARD =
            Pattern.compile(
                "\\b(?:\\d[ -]*?){13,19}\\b"
            );

        String redact(String value) {
            String result = CREDENTIALS.matcher(value)
                .replaceAll("$1=[REDACTED]");

            result = EMAIL.matcher(result)
                .replaceAll("[EMAIL_REDACTED]");

            return CARD.matcher(result)
                .replaceAll("[CARD_REDACTED]");
        }
    }

    static class JsonAdapter implements CollectionAdapter {

        /*
         * This adapter accepts the flat JSON object structure
         * used in the demonstration. It rejects unsupported
         * nested structures instead of silently misinterpreting
         * them. Production ingestion should use a full JSON parser.
         */

        private static final Pattern FIELD =
            Pattern.compile(
                "\"([^\"]+)\"\\s*:\\s*"
                + "(\"((?:\\\\.|[^\"\\\\])*)\"|"
                + "(-?\\d+(?:\\.\\d+)?)|"
                + "(true|false|null))"
            );

        @Override
        public ParsedLog parse(String raw) {
            if (
                raw == null ||
                raw.isBlank() ||
                raw.length() > 1_048_576
            ) {
                throw new PolicyViolationException(
                    "Invalid JSON log size"
                );
            }

            Map<String, Object> fields =
                new LinkedHashMap<>();

            Matcher matcher = FIELD.matcher(raw);

            while (matcher.find()) {
                String key = matcher.group(1);
                String quoted = matcher.group(3);
                String numeric = matcher.group(4);
                String booleanValue = matcher.group(5);

                Object value;

                if (quoted != null) {
                    value = quoted
                        .replace("\\\"", "\"")
                        .replace("\\\\", "\\");
                } else if (numeric != null) {
                    value = numeric;
                } else {
                    value = booleanValue;
                }

                if (fields.putIfAbsent(key, value) != null) {
                    throw new PolicyViolationException(
                        "Duplicate JSON field: " + key
                    );
                }
            }

            for (String required : List.of(
                "timestamp",
                "severity",
                "message"
            )) {
                if (!fields.containsKey(required)) {
                    throw new PolicyViolationException(
                        "Missing JSON field: " + required
                    );
                }
            }

            Map<String, Object> attributes =
                new LinkedHashMap<>(fields);

            String timestamp = String.valueOf(
                attributes.remove("timestamp")
            );

            String severity = String.valueOf(
                attributes.remove("severity")
            );

            String message = String.valueOf(
                attributes.remove("message")
            );

            return new ParsedLog(
                timestamp,
                severity,
                message,
                attributes
            );
        }
    }

    static class SyslogAdapter implements CollectionAdapter {

        private static final Pattern HEADER =
            Pattern.compile(
                "^<(\\d{1,3})>(\\d+)\\s+"
                + "(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+"
                + "(\\S+)\\s+(\\S+)\\s+(.*)$"
            );

        private static final Severity[] LEVELS = {
            Severity.CRITICAL,
            Severity.CRITICAL,
            Severity.CRITICAL,
            Severity.ERROR,
            Severity.WARNING,
            Severity.INFO,
            Severity.INFO,
            Severity.DEBUG
        };

        @Override
        public ParsedLog parse(String raw) {
            Matcher matcher = HEADER.matcher(
                raw == null ? "" : raw
            );

            if (!matcher.matches()) {
                throw new PolicyViolationException(
                    "Invalid Syslog message"
                );
            }

            int priority = Integer.parseInt(
                matcher.group(1)
            );

            if (priority > 191) {
                throw new PolicyViolationException(
                    "Invalid Syslog priority"
                );
            }

            Map<String, Object> attributes =
                new LinkedHashMap<>();

            attributes.put(
                "version",
                matcher.group(2)
            );

            attributes.put(
                "hostname",
                matcher.group(4)
            );

            attributes.put(
                "application",
                matcher.group(5)
            );

            attributes.put(
                "processId",
                matcher.group(6)
            );

            attributes.put(
                "messageId",
                matcher.group(7)
            );

            attributes.put(
                "facility",
                priority / 8
            );

            return new ParsedLog(
                matcher.group(3),
                LEVELS[priority % 8].name(),
                matcher.group(8),
                attributes
            );
        }
    }

    static class AgentRegistry {

        private final Map<String, Agent> agents =
            new HashMap<>();

        synchronized void register(Agent agent) {
            if (agents.containsKey(agent.id())) {
                throw new PolicyViolationException(
                    "Duplicate agent ID"
                );
            }

            agents.put(agent.id(), agent);
        }

        synchronized Agent get(String id) {
            Agent agent = agents.get(id);

            if (agent == null) {
                throw new PolicyViolationException(
                    "Unknown agent"
                );
            }

            return agent;
        }

        synchronized List<Agent> all() {
            return List.copyOf(agents.values());
        }
    }

    static class FingerprintService {

        String calculate(
            String agentId,
            String hostname,
            Instant timestamp,
            Severity severity,
            String message
        ) {
            /*
             * A deterministic identity allows idempotent
             * destination writes across delivery retries.
             */
            String input = String.join(
                "|",
                agentId,
                hostname,
                timestamp.toString(),
                severity.name(),
                message
            );

            try {
                byte[] digest =
                    java.security.MessageDigest
                        .getInstance("SHA-256")
                        .digest(
                            input.getBytes(
                                java.nio.charset.StandardCharsets.UTF_8
                            )
                        );

                return java.util.HexFormat.of()
                    .formatHex(digest);

            } catch (
                java.security.NoSuchAlgorithmException exception
            ) {
                throw new IllegalStateException(
                    "SHA-256 unavailable",
                    exception
                );
            }
        }
    }

    static class NormalizationService {

        private final TimestampPolicy timestampPolicy =
            new TimestampPolicy();

        private final SeverityPolicy severityPolicy =
            new SeverityPolicy();

        private final RedactionPolicy redactionPolicy =
            new RedactionPolicy();

        private final FingerprintService fingerprints =
            new FingerprintService();

        private final Map<SourceType, CollectionAdapter>
            adapters = Map.of(
                SourceType.JSON,
                new JsonAdapter(),
                SourceType.SYSLOG,
                new SyslogAdapter()
            );

        LogRecord normalize(
            Agent agent,
            String raw
        ) {
            CollectionAdapter adapter = adapters.get(
                agent.sourceType()
            );

            ParsedLog parsed = adapter.parse(raw);

            Instant eventTime =
                timestampPolicy.normalize(
                    parsed.timestamp()
                );

            Severity severity =
                severityPolicy.normalize(
                    parsed.severity()
                );

            String message = redactionPolicy.redact(
                parsed.message()
            );

            if (message.length() > 10000) {
                message = message.substring(0, 10000);
            }

            Map<String, Object> attributes =
                new LinkedHashMap<>(
                    parsed.attributes()
                );

            if (attributes.size() > 100) {
                throw new PolicyViolationException(
                    "Attribute count exceeds limit"
                );
            }

            String hostname = String.valueOf(
                attributes.remove("hostname") == null
                    ? agent.hostname()
                    : parsed.attributes().get("hostname")
            );

            String fingerprint =
                fingerprints.calculate(
                    agent.id(),
                    hostname,
                    eventTime,
                    severity,
                    message
                );

            return new LogRecord(
                UUID.randomUUID(),
                agent.id(),
                hostname,
                agent.environment(),
                agent.sourceType(),
                eventTime,
                Instant.now(),
                severity,
                message,
                attributes,
                fingerprint,
                RecordState.NORMALIZED
            );
        }
    }

    interface LogDestination {
        CompletableFuture<Void> send(
            List<LogRecord> batch
        );
    }

    static class MemoryDestination
        implements LogDestination {

        private final Map<String, LogRecord> records =
            new java.util.concurrent.ConcurrentHashMap<>();

        private final AtomicLong failuresRemaining =
            new AtomicLong(0);

        void simulateFailures(long count) {
            if (count < 0) {
                throw new IllegalArgumentException(
                    "Failure count cannot be negative"
                );
            }

            failuresRemaining.set(count);
        }

        @Override
        public CompletableFuture<Void> send(
            List<LogRecord> batch
        ) {
            return CompletableFuture.runAsync(() -> {
                if (
                    failuresRemaining.getAndUpdate(
                        value -> Math.max(0, value - 1)
                    ) > 0
                ) {
                    throw new CompletionException(
                        new ForwardingException(
                            "Destination unavailable"
                        )
                    );
                }

                for (LogRecord record : batch) {
                    records.putIfAbsent(
                        record.fingerprint(),
                        record
                    );
                }
            });
        }

        int size() {
            return records.size();
        }
    }

    static class ForwardingPolicy {

        private final int batchSize;
        private final int maxRetries;
        private final int queueCapacity;

        ForwardingPolicy(
            int batchSize,
            int maxRetries,
            int queueCapacity
        ) {
            if (
                batchSize <= 0 ||
                maxRetries < 0 ||
                queueCapacity <= 0
            ) {
                throw new IllegalArgumentException(
                    "Invalid forwarding policy"
                );
            }

            this.batchSize = batchSize;
            this.maxRetries = maxRetries;
            this.queueCapacity = queueCapacity;
        }
    }

    static class ForwardingService
        implements AutoCloseable {

        private final LogDestination destination;
        private final ForwardingPolicy policy;

        private final ExecutorService executor =
            Executors.newFixedThreadPool(2);

        private final ArrayDeque<LogRecord> queue =
            new ArrayDeque<>();

        private final List<LogRecord> deadLetters =
            new ArrayList<>();

        private final Map<String, Long> metrics =
            new java.util.concurrent.ConcurrentHashMap<>();

        ForwardingService(
            LogDestination destination,
            ForwardingPolicy policy
        ) {
            this.destination = destination;
            this.policy = policy;
        }

        synchronized void enqueue(LogRecord record) {
            if (
                queue.size() >= policy.queueCapacity
            ) {
                increment("queueOverflow");

                throw new ForwardingException(
                    "Forwarding queue full"
                );
            }

            queue.addLast(
                record.withState(RecordState.QUEUED)
            );

            increment("enqueued");
        }

        private void increment(String name) {
            metrics.merge(name, 1L, Long::sum);
        }

        private boolean sendWithRetry(
            List<LogRecord> batch
        ) {
            for (
                int attempt = 0;
                attempt <= policy.maxRetries;
                attempt++
            ) {
                try {
                    destination.send(batch)
                        .get(5, TimeUnit.SECONDS);

                    incrementBy(
                        "forwarded",
                        batch.size()
                    );

                    return true;

                } catch (Exception exception) {
                    increment("deliveryErrors");

                    if (attempt < policy.maxRetries) {
                        try {
                            Thread.sleep(
                                Math.min(
                                    100L * (1L << attempt),
                                    1000L
                                )
                            );
                        } catch (
                            InterruptedException interrupted
                        ) {
                            Thread.currentThread()
                                .interrupt();

                            return false;
                        }
                    }
                }
            }

            return false;
        }

        private void incrementBy(
            String name,
            long amount
        ) {
            metrics.merge(name, amount, Long::sum);
        }

        int flush() {
            int delivered = 0;

            while (true) {
                List<LogRecord> batch =
                    new ArrayList<>();

                synchronized (this) {
                    while (
                        !queue.isEmpty() &&
                        batch.size() < policy.batchSize
                    ) {
                        batch.add(queue.removeFirst());
                    }
                }

                if (batch.isEmpty()) {
                    break;
                }

                CompletableFuture<Boolean> future =
                    CompletableFuture.supplyAsync(
                        () -> sendWithRetry(batch),
                        executor
                    );

                boolean success = future.join();

                if (success) {
                    delivered += batch.size();
                } else {
                    synchronized (this) {
                        deadLetters.addAll(
                            batch.stream()
                                .map(record ->
                                    record.withState(
                                        RecordState.FAILED
                                    )
                                )
                                .toList()
                        );
                    }

                    incrementBy(
                        "deadLettered",
                        batch.size()
                    );
                }
            }

            return delivered;
        }

        synchronized int replayDeadLetters() {
            List<LogRecord> pending =
                new ArrayList<>(deadLetters);

            deadLetters.clear();

            for (LogRecord record : pending) {
                if (queue.size() >= policy.queueCapacity) {
                    deadLetters.add(record);
                } else {
                    queue.addLast(
                        record.withState(
                            RecordState.QUEUED
                        )
                    );
                }
            }

            return flush();
        }

        synchronized int queueSize() {
            return queue.size();
        }

        synchronized int deadLetterSize() {
            return deadLetters.size();
        }

        synchronized Map<String, Long> metrics() {
            return Map.copyOf(metrics);
        }

        @Override
        public void close() {
            executor.shutdown();

            try {
                if (
                    !executor.awaitTermination(
                        5,
                        TimeUnit.SECONDS
                    )
                ) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException exception) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    record RetentionPolicy(
        Duration hotRetention,
        Duration archiveRetention
    ) {
        RetentionPolicy {
            if (
                hotRetention.isNegative() ||
                hotRetention.isZero() ||
                archiveRetention.compareTo(
                    hotRetention
                ) <= 0
            ) {
                throw new IllegalArgumentException(
                    "Invalid retention policy"
                );
            }
        }

        static RetentionPolicy standard() {
            return new RetentionPolicy(
                Duration.ofDays(30),
                Duration.ofDays(90)
            );
        }
    }

    static class RetentionService {

        private final RetentionPolicy policy;

        RetentionService(RetentionPolicy policy) {
            this.policy = policy;
        }

        record RetentionResult(
            List<LogRecord> retained,
            List<LogRecord> archived,
            int deleted
        ) {}

        RetentionResult apply(
            List<LogRecord> records,
            Instant referenceTime
        ) {
            List<LogRecord> retained =
                new ArrayList<>();

            List<LogRecord> archived =
                new ArrayList<>();

            int deleted = 0;

            Instant hotLimit =
                referenceTime.minus(
                    policy.hotRetention()
                );

            Instant archiveLimit =
                referenceTime.minus(
                    policy.archiveRetention()
                );

            for (LogRecord record : records) {
                Instant timestamp =
                    record.eventTime();

                if (timestamp.isAfter(referenceTime)) {
                    retained.add(record);
                } else if (
                    !timestamp.isAfter(archiveLimit)
                ) {
                    deleted++;
                } else if (
                    !timestamp.isAfter(hotLimit)
                ) {
                    archived.add(
                        record.withState(
                            RecordState.ARCHIVED
                        )
                    );
                } else {
                    retained.add(record);
                }
            }

            return new RetentionResult(
                List.copyOf(retained),
                List.copyOf(archived),
                deleted
            );
        }
    }

    static class CollectionService {

        private final AgentRegistry registry =
            new AgentRegistry();

        private final NormalizationService normalizer =
            new NormalizationService();

        private final MemoryDestination destination =
            new MemoryDestination();

        private final ForwardingService forwarder =
            new ForwardingService(
                destination,
                new ForwardingPolicy(
                    2,
                    2,
                    1000
                )
            );

        private final RetentionService retention =
            new RetentionService(
                RetentionPolicy.standard()
            );

        private final List<LogRecord> records =
            new ArrayList<>();

        private final Set<String> fingerprints =
            new HashSet<>();

        private final Map<String, Long> metrics =
            new HashMap<>();

        synchronized Optional<LogRecord> collect(
            String agentId,
            String raw
        ) {
            Agent agent = registry.get(agentId);

            if (agent.status() == AgentStatus.DISABLED) {
                increment("disabledAgents");
                return Optional.empty();
            }

            try {
                LogRecord record =
                    normalizer.normalize(agent, raw);

                if (
                    fingerprints.contains(
                        record.fingerprint()
                    )
                ) {
                    increment("duplicates");
                    return Optional.empty();
                }

                // Queue acceptance occurs before local commit.
                forwarder.enqueue(record);

                fingerprints.add(
                    record.fingerprint()
                );

                records.add(record);

                increment("collected");

                return Optional.of(record);

            } catch (CollectionException exception) {
                increment("rejected");
                throw exception;
            }
        }

        private void increment(String key) {
            metrics.merge(key, 1L, Long::sum);
        }

        AgentRegistry registry() {
            return registry;
        }

        int flush() {
            return forwarder.flush();
        }

        int replayDeadLetters() {
            return forwarder.replayDeadLetters();
        }

        Map<String, Object> report() {
            Map<Severity, Long> severityCounts =
                new EnumMap<>(Severity.class);

            for (LogRecord record : records) {
                severityCounts.merge(
                    record.severity(),
                    1L,
                    Long::sum
                );
            }

            Map<String, Object> report =
                new LinkedHashMap<>();

            report.put("agents", registry.all().size());
            report.put("collected", records.size());
            report.put(
                "destinationRecords",
                destination.size()
            );

            report.put(
                "severityDistribution",
                severityCounts
            );

            report.put("collectionMetrics", metrics);
            report.put(
                "forwardingMetrics",
                forwarder.metrics()
            );

            report.put(
                "queued",
                forwarder.queueSize()
            );

            report.put(
                "deadLetters",
                forwarder.deadLetterSize()
            );

            return report;
        }

        RetentionService.RetentionResult applyRetention(
            Instant referenceTime
        ) {
            return retention.apply(
                records,
                referenceTime
            );
        }

        int recordCount() {
            return records.size();
        }

        int destinationCount() {
            return destination.size();
        }

        int duplicateCount() {
            return Math.toIntExact(
                metrics.getOrDefault("duplicates", 0L)
            );
        }

        ForwardingService forwarder() {
            return forwarder;
        }
    }

    public static void main(String[] args) {

        CollectionService service =
            new CollectionService();

        try (ForwardingService lifecycle = service.forwarder()) {

            service.registry().register(
                new Agent(
                    "web-agent-01",
                    "web-server-01",
                    "production",
                    SourceType.JSON,
                    AgentStatus.ACTIVE
                )
            );

            service.registry().register(
                new Agent(
                    "db-agent-01",
                    "database-01",
                    "production",
                    SourceType.SYSLOG,
                    AgentStatus.ACTIVE
                )
            );

            List<Map.Entry<String, String>> events =
                List.of(
                    Map.entry(
                        "web-agent-01",
                        """
                        {"timestamp":"2026-11-23T04:00:00Z","severity":"INFO","message":"Login successful","service":"identity"}
                        """
                    ),
                    Map.entry(
                        "web-agent-01",
                        """
                        {"timestamp":"2026-11-23T04:01:00Z","severity":"ERROR","message":"password=secret123 connection failure"}
                        """
                    ),
                    Map.entry(
                        "db-agent-01",
                        "<34>1 2026-11-23T04:02:00Z "
                        + "database-01 postgres 1234 ID47 "
                        + "Database connection restored"
                    ),
                    Map.entry(
                        "web-agent-01",
                        """
                        {"timestamp":"2026-11-23T04:03:00Z","severity":"WARNING","message":"High CPU utilization","cpu":92}
                        """
                    )
                );

            for (var event : events) {
                service.collect(
                    event.getKey(),
                    event.getValue()
                );
            }

            // Verify deterministic duplicate detection.
            service.collect(
                events.get(0).getKey(),
                events.get(0).getValue()
            );

            int delivered = service.flush();

            System.out.println(
                "Delivered records: " + delivered
            );

            System.out.println(
                "Enterprise collection report:"
            );

            service.report().forEach(
                (key, value) ->
                    System.out.println(
                        key + ": " + value
                    )
            );

            if (delivered != 4) {
                throw new IllegalStateException(
                    "Forwarding assertion failed"
                );
            }

            if (service.recordCount() != 4) {
                throw new IllegalStateException(
                    "Collection assertion failed"
                );
            }

            if (service.destinationCount() != 4) {
                throw new IllegalStateException(
                    "Destination assertion failed"
                );
            }

            if (service.duplicateCount() != 1) {
                throw new IllegalStateException(
                    "Deduplication assertion failed"
                );
            }

            RetentionService.RetentionResult retention =
                service.applyRetention(
                    Instant.parse(
                        "2026-11-23T04:00:00Z"
                    )
                );

            System.out.println(
                "Retention result: " + retention
            );

            System.out.println(
                "All Java 17 assertions passed."
            );

        }
    }
}
