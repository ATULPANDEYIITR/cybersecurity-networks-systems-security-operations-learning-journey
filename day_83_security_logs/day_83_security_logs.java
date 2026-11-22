import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/*
 * Enterprise Security Log Management and Threat Detection
 *
 * Java 17
 *
 * Domains:
 * - Windows security auditing
 * - Linux authentication logs
 * - Firewall telemetry
 * - DNS monitoring
 * - Proxy monitoring
 * - Application security events
 *
 * Enterprise capabilities:
 * - Immutable event records
 * - Typed domain model
 * - Configurable detection policies
 * - Event validation
 * - Sliding-window correlation
 * - Approval-independent security alerts
 * - Incident classification
 * - Risk scoring
 * - State transitions
 * - Alert deduplication
 *
 * Compile:
 * javac SecurityLogs.java
 *
 * Run:
 * java SecurityLogs
 */

public class SecurityLogs {

    enum Source {
        WINDOWS,
        LINUX,
        FIREWALL,
        DNS,
        PROXY,
        AUTHENTICATION,
        APPLICATION
    }

    enum EventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        PRIVILEGE_CHANGE,
        PROCESS_EXECUTION,
        NETWORK_CONNECTION,
        FIREWALL_BLOCK,
        FIREWALL_ALLOW,
        DNS_QUERY,
        HTTP_REQUEST,
        APPLICATION_ERROR,
        FILE_ACCESS
    }

    enum Severity {
        INFO(0),
        LOW(10),
        MEDIUM(25),
        HIGH(45),
        CRITICAL(70);

        private final int weight;

        Severity(int weight) {
            this.weight = weight;
        }

        public int weight() {
            return weight;
        }
    }

    enum IncidentState {
        OPEN,
        INVESTIGATING,
        CONTAINED,
        RESOLVED,
        CLOSED
    }

    record SecurityEvent(
        String id,
        Instant timestamp,
        Source source,
        EventType type,
        String sourceIp,
        String destinationIp,
        String username,
        String hostname,
        Integer destinationPort,
        String protocol,
        String resource,
        Map<String, String> attributes
    ) {
        SecurityEvent {
            Objects.requireNonNull(id);
            Objects.requireNonNull(timestamp);
            Objects.requireNonNull(source);
            Objects.requireNonNull(type);

            if (id.isBlank() || id.length() > 128) {
                throw new IllegalArgumentException(
                    "Invalid event identifier."
                );
            }

            validateIp(sourceIp);
            validateIp(destinationIp);

            if (destinationPort != null &&
                (destinationPort < 1 || destinationPort > 65535)) {
                throw new IllegalArgumentException(
                    "Invalid destination port."
                );
            }

            attributes = Map.copyOf(
                attributes == null ? Map.of() : attributes
            );

            if (resource != null && resource.length() > 8192) {
                throw new IllegalArgumentException(
                    "Resource exceeds allowed length."
                );
            }
        }

        private static void validateIp(String value) {
            if (value == null) return;

            try {
                InetAddress.getByName(value);
            } catch (UnknownHostException exception) {
                throw new IllegalArgumentException(
                    "Invalid IP address: " + value
                );
            }

            // Prevent DNS hostname input from being accepted as an IP.
            if (!value.contains(":") &&
                value.chars().filter(c -> c == '.').count() != 3) {
                throw new IllegalArgumentException(
                    "Expected an IP address."
                );
            }
        }
    }

    record DetectionRule(
        String id,
        String title,
        Severity severity,
        double confidence
    ) {
        DetectionRule {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("Rule ID required.");
            }

            Objects.requireNonNull(severity);

            if (confidence < 0 || confidence > 1) {
                throw new IllegalArgumentException(
                    "Confidence must be between zero and one."
                );
            }
        }
    }

    record SecurityFinding(
        DetectionRule rule,
        String entity,
        List<String> eventIds,
        Map<String, String> evidence,
        Instant timestamp
    ) {
        SecurityFinding {
            eventIds = List.copyOf(eventIds);
            evidence = Map.copyOf(evidence);
        }

        int riskScore() {
            return Math.min(
                100,
                (int) Math.round(
                    rule.severity().weight() *
                    rule.confidence()
                )
            );
        }
    }

    record DetectionPolicy(
        int failedLoginThreshold,
        int portScanThreshold,
        Duration window,
        int dnsLabelThreshold,
        int minimumRisk
    ) {
        DetectionPolicy {
            if (
                failedLoginThreshold < 1 ||
                portScanThreshold < 1 ||
                window.isNegative() ||
                window.isZero() ||
                dnsLabelThreshold < 1 ||
                minimumRisk < 0 ||
                minimumRisk > 100
            ) {
                throw new IllegalArgumentException(
                    "Invalid detection policy."
                );
            }
        }

        static DetectionPolicy standard() {
            return new DetectionPolicy(
                5,
                10,
                Duration.ofMinutes(5),
                50,
                20
            );
        }
    }

    static class EventStore {
        private final Map<String, SecurityEvent> events =
            new LinkedHashMap<>();

        public synchronized void append(SecurityEvent event) {
            Objects.requireNonNull(event);

            if (events.containsKey(event.id())) {
                throw new IllegalArgumentException(
                    "Duplicate event ID: " + event.id()
                );
            }

            events.put(event.id(), event);
        }

        public synchronized List<SecurityEvent> snapshot() {
            return List.copyOf(events.values());
        }

        public synchronized int size() {
            return events.size();
        }
    }

    static class AlertRegistry {
        private final Map<String, Instant> lastEmitted =
            new HashMap<>();

        private final Duration cooldown;

        AlertRegistry(Duration cooldown) {
            this.cooldown = cooldown;
        }

        synchronized boolean allow(
            SecurityFinding finding
        ) {
            String key =
                finding.rule().id() + ":" + finding.entity();

            Instant previous = lastEmitted.get(key);

            if (
                previous != null &&
                Duration.between(
                    previous,
                    finding.timestamp()
                ).compareTo(cooldown) < 0
            ) {
                return false;
            }

            lastEmitted.put(key, finding.timestamp());

            return true;
        }
    }

    static class Incident {
        private final String id;
        private final SecurityFinding finding;
        private IncidentState state;
        private final List<String> history = new ArrayList<>();

        Incident(SecurityFinding finding) {
            this.id = UUID.randomUUID().toString();
            this.finding = finding;
            this.state = IncidentState.OPEN;
            history.add("OPEN");
        }

        public synchronized void transition(
            IncidentState next
        ) {
            Objects.requireNonNull(next);

            boolean allowed = switch (state) {
                case OPEN ->
                    next == IncidentState.INVESTIGATING ||
                    next == IncidentState.CLOSED;

                case INVESTIGATING ->
                    next == IncidentState.CONTAINED ||
                    next == IncidentState.RESOLVED;

                case CONTAINED ->
                    next == IncidentState.INVESTIGATING ||
                    next == IncidentState.RESOLVED;

                case RESOLVED ->
                    next == IncidentState.CLOSED ||
                    next == IncidentState.INVESTIGATING;

                case CLOSED -> false;
            };

            if (!allowed) {
                throw new IllegalStateException(
                    "Invalid incident transition: " +
                    state + " -> " + next
                );
            }

            state = next;
            history.add(next.name());
        }

        public String id() {
            return id;
        }

        public IncidentState state() {
            return state;
        }

        public SecurityFinding finding() {
            return finding;
        }

        public List<String> history() {
            return List.copyOf(history);
        }
    }

    static class DetectionService {
        private final DetectionPolicy policy;

        private static final DetectionRule BRUTE_FORCE =
            new DetectionRule(
                "AUTH-001",
                "Repeated authentication failures",
                Severity.HIGH,
                0.95
            );

        private static final DetectionRule PORT_SCAN =
            new DetectionRule(
                "NET-001",
                "Potential port scan",
                Severity.HIGH,
                0.90
            );

        private static final DetectionRule DNS_ANOMALY =
            new DetectionRule(
                "DNS-001",
                "Suspicious DNS query",
                Severity.MEDIUM,
                0.85
            );

        private static final DetectionRule PROXY_ANOMALY =
            new DetectionRule(
                "PROXY-001",
                "Executable download detected",
                Severity.MEDIUM,
                0.80
            );

        private static final DetectionRule PRIVILEGE_CHANGE =
            new DetectionRule(
                "AUTH-002",
                "Privilege change detected",
                Severity.MEDIUM,
                0.85
            );

        DetectionService(DetectionPolicy policy) {
            this.policy = Objects.requireNonNull(policy);
        }

        private List<List<SecurityEvent>> windows(
            List<SecurityEvent> records
        ) {
            List<SecurityEvent> sorted = records.stream()
                .sorted(Comparator.comparing(
                    SecurityEvent::timestamp
                ))
                .toList();

            List<List<SecurityEvent>> result = new ArrayList<>();

            int start = 0;

            for (int end = 0; end < sorted.size(); end++) {
                while (
                    Duration.between(
                        sorted.get(start).timestamp(),
                        sorted.get(end).timestamp()
                    ).compareTo(policy.window()) > 0
                ) {
                    start++;
                }

                result.add(
                    sorted.subList(start, end + 1)
                );
            }

            return result;
        }

        private List<SecurityFinding> detectBruteForce(
            List<SecurityEvent> events
        ) {
            Map<String, List<SecurityEvent>> groups =
                events.stream()
                    .filter(e ->
                        e.type() == EventType.LOGIN_FAILURE &&
                        e.sourceIp() != null
                    )
                    .collect(Collectors.groupingBy(
                        e -> e.sourceIp() + ":" +
                            Objects.toString(
                                e.username(),
                                "unknown"
                            )
                    ));

            List<SecurityFinding> findings = new ArrayList<>();

            for (var entry : groups.entrySet()) {
                for (List<SecurityEvent> window :
                    windows(entry.getValue())) {

                    if (window.size() <
                        policy.failedLoginThreshold()) {
                        continue;
                    }

                    findings.add(new SecurityFinding(
                        BRUTE_FORCE,
                        entry.getKey(),
                        window.stream()
                            .map(SecurityEvent::id)
                            .toList(),
                        Map.of(
                            "attempts",
                            String.valueOf(window.size())
                        ),
                        window.get(window.size() - 1).timestamp()
                    ));

                    break;
                }
            }

            return findings;
        }

        private List<SecurityFinding> detectPortScan(
            List<SecurityEvent> events
        ) {
            Map<String, List<SecurityEvent>> groups =
                events.stream()
                    .filter(e ->
                        e.type() == EventType.NETWORK_CONNECTION &&
                        e.sourceIp() != null &&
                        e.destinationPort() != null
                    )
                    .collect(Collectors.groupingBy(
                        SecurityEvent::sourceIp
                    ));

            List<SecurityFinding> findings = new ArrayList<>();

            for (var entry : groups.entrySet()) {
                for (List<SecurityEvent> window :
                    windows(entry.getValue())) {

                    Set<Integer> ports = window.stream()
                        .map(SecurityEvent::destinationPort)
                        .collect(Collectors.toSet());

                    if (ports.size() <
                        policy.portScanThreshold()) {
                        continue;
                    }

                    findings.add(new SecurityFinding(
                        PORT_SCAN,
                        entry.getKey(),
                        window.stream()
                            .map(SecurityEvent::id)
                            .toList(),
                        Map.of(
                            "uniquePorts",
                            String.valueOf(ports.size())
                        ),
                        window.get(window.size() - 1).timestamp()
                    ));

                    break;
                }
            }

            return findings;
        }

        private List<SecurityFinding> detectDns(
            List<SecurityEvent> events
        ) {
            List<SecurityFinding> findings = new ArrayList<>();

            for (SecurityEvent event : events) {
                if (event.type() != EventType.DNS_QUERY) {
                    continue;
                }

                String domain = event.attributes()
                    .getOrDefault("query", "")
                    .toLowerCase();

                if (domain.isBlank()) continue;

                int longest = java.util.Arrays.stream(
                    domain.split("\\.")
                ).mapToInt(String::length).max().orElse(0);

                double entropy = entropy(domain);

                if (
                    longest >= policy.dnsLabelThreshold() ||
                    (domain.length() >= 25 && entropy >= 3.5)
                ) {
                    findings.add(new SecurityFinding(
                        DNS_ANOMALY,
                        Objects.toString(
                            event.sourceIp(),
                            "unknown"
                        ),
                        List.of(event.id()),
                        Map.of(
                            "domain", domain,
                            "entropy", String.format(
                                "%.3f", entropy
                            )
                        ),
                        event.timestamp()
                    ));
                }
            }

            return findings;
        }

        private List<SecurityFinding> detectProxy(
            List<SecurityEvent> events
        ) {
            List<SecurityFinding> findings = new ArrayList<>();

            Set<String> extensions = Set.of(
                ".exe", ".dll", ".ps1",
                ".bat", ".scr", ".vbs"
            );

            for (SecurityEvent event : events) {
                if (
                    event.type() != EventType.HTTP_REQUEST ||
                    event.resource() == null
                ) {
                    continue;
                }

                try {
                    String path = URI.create(
                        event.resource()
                    ).getPath();

                    if (path == null) continue;

                    String normalized = path.toLowerCase();

                    if (extensions.stream().anyMatch(
                        normalized::endsWith
                    )) {
                        findings.add(new SecurityFinding(
                            PROXY_ANOMALY,
                            Objects.toString(
                                event.sourceIp(),
                                "unknown"
                            ),
                            List.of(event.id()),
                            Map.of(
                                "resource",
                                event.resource()
                            ),
                            event.timestamp()
                        ));
                    }
                } catch (IllegalArgumentException ignored) {
                    // Invalid URLs are rejected from this detection rule.
                }
            }

            return findings;
        }

        private List<SecurityFinding> detectPrivilegeChanges(
            List<SecurityEvent> events
        ) {
            List<SecurityFinding> findings = new ArrayList<>();

            for (SecurityEvent event : events) {
                if (
                    event.type() != EventType.PRIVILEGE_CHANGE
                ) {
                    continue;
                }

                findings.add(new SecurityFinding(
                    PRIVILEGE_CHANGE,
                    Objects.toString(
                        event.username(),
                        "unknown"
                    ),
                    List.of(event.id()),
                    Map.of(
                        "hostname",
                        Objects.toString(
                            event.hostname(),
                            "unknown"
                        )
                    ),
                    event.timestamp()
                ));
            }

            return findings;
        }

        private static double entropy(String value) {
            if (value.isEmpty()) return 0.0;

            Map<Character, Integer> counts = new HashMap<>();

            for (char c : value.toCharArray()) {
                counts.merge(c, 1, Integer::sum);
            }

            double result = 0.0;

            for (int count : counts.values()) {
                double probability =
                    (double) count / value.length();

                result -= probability *
                    (Math.log(probability) / Math.log(2));
            }

            return result;
        }

        public List<SecurityFinding> evaluate(
            List<SecurityEvent> events
        ) {
            List<SecurityFinding> findings = new ArrayList<>();

            findings.addAll(detectBruteForce(events));
            findings.addAll(detectPortScan(events));
            findings.addAll(detectDns(events));
            findings.addAll(detectProxy(events));
            findings.addAll(detectPrivilegeChanges(events));

            return findings.stream()
                .filter(f -> f.riskScore() >= policy.minimumRisk())
                .sorted(
                    Comparator.comparingInt(
                        SecurityFinding::riskScore
                    ).reversed()
                )
                .toList();
        }
    }

    static class SecurityReportService {
        public void print(
            List<SecurityEvent> events,
            List<SecurityFinding> findings
        ) {
            Map<Source, Long> sourceCounts =
                events.stream().collect(
                    Collectors.groupingBy(
                        SecurityEvent::source,
                        Collectors.counting()
                    )
                );

            Map<Severity, Long> severityCounts =
                findings.stream().collect(
                    Collectors.groupingBy(
                        f -> f.rule().severity(),
                        Collectors.counting()
                    )
                );

            System.out.println(
                "\n========== SECURITY REPORT =========="
            );

            System.out.println(
                "Events processed: " + events.size()
            );

            System.out.println(
                "Findings detected: " + findings.size()
            );

            System.out.println("\nSource distribution:");

            sourceCounts.forEach(
                (source, count) ->
                    System.out.println(source + ": " + count)
            );

            System.out.println("\nSecurity findings:");

            for (SecurityFinding finding : findings) {
                System.out.println(
                    "\n" + finding.rule().id() +
                    " | " + finding.rule().title()
                );

                System.out.println(
                    "Severity: " +
                    finding.rule().severity()
                );

                System.out.println(
                    "Entity: " + finding.entity()
                );

                System.out.println(
                    "Risk: " + finding.riskScore() + "/100"
                );

                System.out.println(
                    "Evidence: " + finding.evidence()
                );
            }

            System.out.println("\nSeverity distribution:");
            System.out.println(severityCounts);
        }
    }

    static List<SecurityEvent> sampleEvents() {
        Instant now = Instant.parse(
            "2026-11-22T07:30:00Z"
        );

        List<SecurityEvent> events = new ArrayList<>();

        for (int i = 0; i < 7; i++) {
            events.add(new SecurityEvent(
                "auth-" + i,
                now.minusSeconds(60 - i * 5L),
                Source.AUTHENTICATION,
                EventType.LOGIN_FAILURE,
                "203.0.113.50",
                null,
                "administrator",
                "server-01",
                null,
                null,
                null,
                Map.of()
            ));
        }

        for (int i = 0; i < 12; i++) {
            events.add(new SecurityEvent(
                "network-" + i,
                now.minusSeconds(40 - i),
                Source.FIREWALL,
                EventType.NETWORK_CONNECTION,
                "198.51.100.20",
                "10.0.0.10",
                null,
                "firewall-01",
                1000 + i,
                "TCP",
                null,
                Map.of()
            ));
        }

        events.add(new SecurityEvent(
            "dns-001",
            now,
            Source.DNS,
            EventType.DNS_QUERY,
            "10.0.0.15",
            null,
            null,
            "dns-01",
            null,
            null,
            null,
            Map.of(
                "query",
                "a".repeat(65) + ".example.com"
            )
        ));

        events.add(new SecurityEvent(
            "proxy-001",
            now,
            Source.PROXY,
            EventType.HTTP_REQUEST,
            "10.0.0.15",
            null,
            "employee01",
            "proxy-01",
            null,
            "HTTPS",
            "https://example.com/payload.exe",
            Map.of()
        ));

        events.add(new SecurityEvent(
            "priv-001",
            now,
            Source.WINDOWS,
            EventType.PRIVILEGE_CHANGE,
            null,
            null,
            "administrator",
            "server-01",
            null,
            null,
            null,
            Map.of()
        ));

        return events;
    }

    static void runTests() {
        DetectionPolicy policy = new DetectionPolicy(
            3,
            5,
            Duration.ofMinutes(5),
            50,
            20
        );

        DetectionService service =
            new DetectionService(policy);

        List<SecurityFinding> findings =
            service.evaluate(sampleEvents());

        if (findings.stream().noneMatch(
            f -> f.rule().id().equals("AUTH-001")
        )) {
            throw new AssertionError(
                "Brute-force detection failed."
            );
        }

        if (findings.stream().noneMatch(
            f -> f.rule().id().equals("NET-001")
        )) {
            throw new AssertionError(
                "Port-scan detection failed."
            );
        }

        if (findings.stream().noneMatch(
            f -> f.rule().id().equals("DNS-001")
        )) {
            throw new AssertionError(
                "DNS detection failed."
            );
        }

        Incident incident = new Incident(findings.get(0));

        incident.transition(IncidentState.INVESTIGATING);
        incident.transition(IncidentState.RESOLVED);
        incident.transition(IncidentState.CLOSED);

        if (incident.state() != IncidentState.CLOSED) {
            throw new AssertionError(
                "Incident state transition failed."
            );
        }

        System.out.println("All Java 17 tests passed.");
    }

    public static void main(String[] args) {
        try {
            if (
                args.length > 0 &&
                args[0].equals("--test")
            ) {
                runTests();
                return;
            }

            EventStore store = new EventStore();

            for (SecurityEvent event : sampleEvents()) {
                store.append(event);
            }

            DetectionService detection =
                new DetectionService(
                    DetectionPolicy.standard()
                );

            List<SecurityFinding> findings =
                detection.evaluate(store.snapshot());

            AlertRegistry registry =
                new AlertRegistry(Duration.ofMinutes(5));

            List<SecurityFinding> alerts =
                findings.stream()
                    .filter(registry::allow)
                    .toList();

            SecurityReportService reporting =
                new SecurityReportService();

            reporting.print(store.snapshot(), alerts);

        } catch (Exception exception) {
            System.err.println(
                "Security processing failure: " +
                exception.getMessage()
            );

            System.exit(1);
        }
    }
}
