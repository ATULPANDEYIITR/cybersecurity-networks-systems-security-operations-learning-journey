import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/*
 * Enterprise IOC Investigation and Threat Intelligence Platform
 *
 * Java 17
 * No third-party dependencies.
 *
 * Enterprise capabilities:
 * - Strong domain types
 * - Indicator lifecycle management
 * - Typed IOC normalization
 * - Threat intelligence provenance
 * - Confidence and severity policies
 * - Event correlation
 * - Allowlist governance
 * - Investigation workflow
 * - Analyst assignment
 * - Immutable audit records
 * - Policy-driven case prioritization
 * - Validation and failure handling
 */

public class IOCInvestigation {

    enum IOCType {
        IP, DOMAIN, HASH, URL, FILENAME, REGISTRY
    }

    enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    enum CaseStatus {
        OPEN, INVESTIGATING, CONTAINED, CLOSED
    }

    enum EventSource {
        FIREWALL, DNS, ENDPOINT, PROXY, FILESYSTEM, REGISTRY
    }

    enum AuditAction {
        IOC_REGISTERED,
        EVENT_MATCHED,
        EVENT_ALLOWLISTED,
        CASE_CREATED,
        CASE_TRANSITIONED,
        CASE_ASSIGNED
    }

    static class ValidationException extends RuntimeException {
        ValidationException(String message) {
            super(message);
        }
    }

    static class PolicyException extends RuntimeException {
        PolicyException(String message) {
            super(message);
        }
    }

    record AuditRecord(
        String id,
        AuditAction action,
        String actor,
        String resource,
        Instant timestamp,
        String description
    ) {}

    record ThreatSource(
        String name,
        String feedReference,
        String organization,
        Instant receivedAt
    ) {
        ThreatSource {
            if (name == null || name.isBlank()) {
                throw new ValidationException("Source name required");
            }

            if (feedReference == null || feedReference.isBlank()) {
                throw new ValidationException("Feed reference required");
            }

            Objects.requireNonNull(organization);
            Objects.requireNonNull(receivedAt);
        }
    }

    record IndicatorKey(IOCType type, String value) {}

    record SecurityEvent(
        String id,
        EventSource source,
        IOCType type,
        String value,
        String asset,
        Instant timestamp,
        String tenantId
    ) {
        SecurityEvent {
            if (id == null || id.isBlank() ||
                asset == null || asset.isBlank() ||
                tenantId == null || tenantId.isBlank()) {
                throw new ValidationException(
                    "Event ID, asset and tenant are required"
                );
            }

            Objects.requireNonNull(source);
            Objects.requireNonNull(type);
            Objects.requireNonNull(timestamp);
        }
    }

    record IOCMatch(
        String eventId,
        String indicatorId,
        String asset,
        String tenantId,
        IOCType type,
        String value,
        int confidence,
        Severity severity,
        Instant matchedAt
    ) {}

    record Policy(
        int minimumConfidence,
        int minimumRequiredApprovals,
        boolean requireIndependentSources
    ) {
        Policy {
            if (minimumConfidence < 0 || minimumConfidence > 100) {
                throw new ValidationException(
                    "Confidence threshold must be 0-100"
                );
            }

            if (minimumRequiredApprovals < 0) {
                throw new ValidationException(
                    "Invalid approval threshold"
                );
            }
        }
    }

    static final class Indicator {
        private final String id;
        private final IOCType type;
        private final String value;
        private final ThreatSource source;
        private final int confidence;
        private final Severity severity;
        private final Set<String> tags;
        private final Instant createdAt;
        private final Instant expiresAt;
        private boolean active;

        Indicator(
            IOCType type,
            String value,
            ThreatSource source,
            int confidence,
            Severity severity,
            Set<String> tags,
            Instant expiresAt
        ) {
            this.type = Objects.requireNonNull(type);
            this.value = normalize(type, value);
            this.source = Objects.requireNonNull(source);

            if (confidence < 0 || confidence > 100) {
                throw new ValidationException(
                    "Confidence must be 0-100"
                );
            }

            this.confidence = confidence;
            this.severity = Objects.requireNonNull(severity);

            Set<String> normalizedTags = new HashSet<>();

            for (String tag : tags) {
                if (tag != null && !tag.isBlank()) {
                    normalizedTags.add(tag.trim().toLowerCase());
                }
            }

            this.tags = Collections.unmodifiableSet(normalizedTags);
            this.createdAt = Instant.now();
            this.expiresAt = expiresAt;
            this.active = true;

            if (expiresAt != null && !expiresAt.isAfter(createdAt)) {
                throw new ValidationException(
                    "Expiration must be in the future"
                );
            }

            this.id = UUID.randomUUID().toString();
        }

        String id() {
            return id;
        }

        IOCType type() {
            return type;
        }

        String value() {
            return value;
        }

        int confidence() {
            return confidence;
        }

        Severity severity() {
            return severity;
        }

        ThreatSource source() {
            return source;
        }

        Set<String> tags() {
            return tags;
        }

        boolean isActive(Instant now) {
            return active &&
                (expiresAt == null || expiresAt.isAfter(now));
        }

        void deactivate() {
            active = false;
        }
    }

    static String normalize(IOCType type, String raw) {
        if (raw == null || raw.isBlank() || raw.length() > 4096) {
            throw new ValidationException("Invalid IOC value");
        }

        String value = raw.trim();

        switch (type) {
            case IP:
                return normalizeIP(value);

            case DOMAIN:
                return normalizeDomain(value);

            case HASH:
                String hash = value.toLowerCase();

                if (!Pattern.matches(
                    "(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})",
                    hash
                )) {
                    throw new ValidationException("Invalid hash");
                }

                return hash;

            case URL:
                return normalizeURL(value);

            case FILENAME:
                if (value.length() > 255 ||
                    value.matches(".*[/\\\\\\x00\\r\\n].*")) {
                    throw new ValidationException("Invalid filename");
                }

                return value.toLowerCase();

            case REGISTRY:
                return normalizeRegistry(value);

            default:
                throw new ValidationException("Unsupported IOC type");
        }
    }

    static String normalizeIP(String value) {
        if (value.contains(":")) {
            String candidate = value.toLowerCase();

            if (!candidate.matches("[0-9a-f:.]+") ||
                !candidate.contains(":") ||
                candidate.length() > 45) {
                throw new ValidationException("Invalid IPv6 address");
            }

            try {
                java.net.InetAddress address =
                    java.net.InetAddress.getByName(candidate);

                if (!(address instanceof java.net.Inet6Address)) {
                    throw new ValidationException("Invalid IPv6 address");
                }

                return address.getHostAddress().toLowerCase();
            } catch (Exception exception) {
                throw new ValidationException("Invalid IPv6 address");
            }
        }

        String[] parts = value.split("\\.", -1);

        if (parts.length != 4) {
            throw new ValidationException("Invalid IPv4 address");
        }

        for (String part : parts) {
            if (!part.matches("0|[1-9][0-9]{0,2}")) {
                throw new ValidationException("Invalid IPv4 octet");
            }

            if (Integer.parseInt(part) > 255) {
                throw new ValidationException("IPv4 octet exceeds 255");
            }
        }

        return String.join(".", parts);
    }

    static String normalizeDomain(String value) {
        value = value.replaceFirst("\\.$", "").toLowerCase();

        final String ascii;

        try {
            ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES);
        } catch (IllegalArgumentException exception) {
            throw new ValidationException("Invalid domain");
        }

        if (ascii.length() > 253 || !ascii.contains(".")) {
            throw new ValidationException("Invalid FQDN");
        }

        for (String label : ascii.split("\\.")) {
            if (label.isEmpty() || label.length() > 63) {
                throw new ValidationException("Invalid domain label");
            }
        }

        return ascii;
    }

    static String normalizeURL(String value) {
        try {
            URI uri = new URI(value);

            if (!"http".equalsIgnoreCase(uri.getScheme()) &&
                !"https".equalsIgnoreCase(uri.getScheme())) {
                throw new ValidationException("Unsupported URL scheme");
            }

            if (uri.getHost() == null ||
                uri.getRawUserInfo() != null) {
                throw new ValidationException("Invalid URL authority");
            }

            String host = uri.getHost();

            if (host.contains(":")) {
                host = normalizeIP(host);
            } else {
                host = normalizeDomain(host);
            }

            if (uri.getPort() > 65535) {
                throw new ValidationException("Invalid URL port");
            }

            return new URI(
                uri.getScheme().toLowerCase(),
                null,
                host,
                uri.getPort(),
                uri.getRawPath().isEmpty() ? "/" : uri.getRawPath(),
                uri.getRawQuery(),
                null
            ).toASCIIString();

        } catch (URISyntaxException exception) {
            throw new ValidationException("Malformed URL");
        }
    }

    static String normalizeRegistry(String value) {
        String normalized = value
            .replaceFirst("(?i)^HKEY_LOCAL_MACHINE", "HKLM")
            .replaceFirst("(?i)^HKEY_CURRENT_USER", "HKCU")
            .replaceFirst("(?i)^HKEY_CLASSES_ROOT", "HKCR")
            .replaceFirst("(?i)^HKEY_USERS", "HKU");

        if (!normalized.matches("(?i)^HK(LM|CU|CR|U)\\\\.+")) {
            throw new ValidationException("Invalid registry root");
        }

        return normalized.toLowerCase();
    }

    static final class IOCRepository {
        private final Map<IndicatorKey, Indicator> indicators =
            new HashMap<>();

        private final Set<IndicatorKey> allowlist = new HashSet<>();

        private final List<AuditRecord> audit = new ArrayList<>();

        void register(Indicator indicator, String actor) {
            IndicatorKey key = new IndicatorKey(
                indicator.type(),
                indicator.value()
            );

            if (indicators.containsKey(key)) {
                throw new PolicyException("Duplicate IOC");
            }

            indicators.put(key, indicator);

            audit.add(new AuditRecord(
                UUID.randomUUID().toString(),
                AuditAction.IOC_REGISTERED,
                actor,
                indicator.id(),
                Instant.now(),
                "Indicator registered"
            ));
        }

        Indicator find(IOCType type, String value) {
            return indicators.get(
                new IndicatorKey(type, normalize(type, value))
            );
        }

        void allow(IOCType type, String value, String actor) {
            allowlist.add(
                new IndicatorKey(type, normalize(type, value))
            );

            audit.add(new AuditRecord(
                UUID.randomUUID().toString(),
                AuditAction.EVENT_ALLOWLISTED,
                actor,
                value,
                Instant.now(),
                "Indicator allowlisted"
            ));
        }

        boolean isAllowed(IOCType type, String value) {
            return allowlist.contains(new IndicatorKey(type, value));
        }

        List<Indicator> activeIndicators() {
            return indicators.values().stream()
                .filter(item -> item.isActive(Instant.now()))
                .toList();
        }

        List<AuditRecord> auditRecords() {
            return List.copyOf(audit);
        }
    }

    static final class DetectionService {
        private final IOCRepository repository;
        private final Policy policy;

        DetectionService(IOCRepository repository, Policy policy) {
            this.repository = Objects.requireNonNull(repository);
            this.policy = Objects.requireNonNull(policy);
        }

        java.util.Optional<IOCMatch> evaluate(SecurityEvent event) {
            String normalized = normalize(event.type(), event.value());

            Indicator indicator = repository.find(
                event.type(), normalized
            );

            if (indicator == null ||
                !indicator.isActive(Instant.now())) {
                return java.util.Optional.empty();
            }

            if (repository.isAllowed(event.type(), normalized)) {
                return java.util.Optional.empty();
            }

            if (indicator.confidence() < policy.minimumConfidence()) {
                return java.util.Optional.empty();
            }

            return java.util.Optional.of(new IOCMatch(
                event.id(),
                indicator.id(),
                event.asset(),
                event.tenantId(),
                indicator.type(),
                indicator.value(),
                indicator.confidence(),
                indicator.severity(),
                Instant.now()
            ));
        }

        List<IOCMatch> evaluateBatch(List<SecurityEvent> events) {
            return events.stream()
                .map(this::evaluate)
                .flatMap(java.util.Optional::stream)
                .toList();
        }
    }

    static final class Investigation {
        private final String id;
        private final String title;
        private final String tenantId;
        private final List<IOCMatch> matches = new ArrayList<>();
        private final List<String> notes = new ArrayList<>();

        private CaseStatus status = CaseStatus.OPEN;
        private String assignedAnalyst;

        Investigation(String id, String title, String tenantId) {
            if (id == null || id.isBlank() ||
                title == null || title.isBlank() ||
                tenantId == null || tenantId.isBlank()) {
                throw new ValidationException(
                    "Investigation fields required"
                );
            }

            this.id = id;
            this.title = title;
            this.tenantId = tenantId;
        }

        void assign(String analyst) {
            ensureNotClosed();

            if (analyst == null || analyst.isBlank()) {
                throw new ValidationException("Analyst required");
            }

            assignedAnalyst = analyst;
        }

        void addMatch(IOCMatch match) {
            ensureNotClosed();

            if (!tenantId.equals(match.tenantId())) {
                throw new PolicyException("Cross-tenant match rejected");
            }

            boolean duplicate = matches.stream().anyMatch(
                existing ->
                    existing.eventId().equals(match.eventId()) &&
                    existing.indicatorId().equals(match.indicatorId())
            );

            if (!duplicate) {
                matches.add(match);
            }
        }

        void addNote(String note) {
            ensureNotClosed();

            if (note == null || note.isBlank()) {
                throw new ValidationException("Empty investigation note");
            }

            notes.add(Instant.now() + " | " + note);
        }

        void transition(CaseStatus next) {
            ensureNotClosed();

            Map<CaseStatus, Set<CaseStatus>> transitions =
                new EnumMap<>(CaseStatus.class);

            transitions.put(
                CaseStatus.OPEN,
                Set.of(CaseStatus.INVESTIGATING, CaseStatus.CLOSED)
            );

            transitions.put(
                CaseStatus.INVESTIGATING,
                Set.of(CaseStatus.CONTAINED, CaseStatus.CLOSED)
            );

            transitions.put(
                CaseStatus.CONTAINED,
                Set.of(CaseStatus.INVESTIGATING, CaseStatus.CLOSED)
            );

            transitions.put(CaseStatus.CLOSED, Set.of());

            if (!transitions.get(status).contains(next)) {
                throw new PolicyException("Invalid case transition");
            }

            status = next;
        }

        private void ensureNotClosed() {
            if (status == CaseStatus.CLOSED) {
                throw new PolicyException("Investigation is closed");
            }
        }

        String id() {
            return id;
        }

        String title() {
            return title;
        }

        CaseStatus status() {
            return status;
        }

        List<IOCMatch> matches() {
            return List.copyOf(matches);
        }

        String assignedAnalyst() {
            return assignedAnalyst;
        }
    }

    static final class RiskScoringService {
        private static final Map<Severity, Integer> WEIGHTS =
            Map.of(
                Severity.LOW, 1,
                Severity.MEDIUM, 2,
                Severity.HIGH, 3,
                Severity.CRITICAL, 4
            );

        int calculate(List<IOCMatch> matches) {
            return matches.stream()
                .mapToInt(match ->
                    match.confidence() *
                    WEIGHTS.get(match.severity()) / 4
                )
                .max()
                .orElse(0);
        }

        Severity classify(int score) {
            if (score >= 90) return Severity.CRITICAL;
            if (score >= 70) return Severity.HIGH;
            if (score >= 40) return Severity.MEDIUM;

            return Severity.LOW;
        }
    }

    static void runTests() {
        if (!normalizeDomain("MALWARE.EXAMPLE.").equals(
            "malware.example"
        )) {
            throw new AssertionError("Domain normalization failed");
        }

        if (!normalizeHash("A".repeat(64)).equals(
            "a".repeat(64)
        )) {
            throw new AssertionError("Hash normalization failed");
        }

        boolean rejected = false;

        try {
            normalizeIP("999.999.999.999");
        } catch (ValidationException exception) {
            rejected = true;
        }

        if (!rejected) {
            throw new AssertionError("Invalid IP accepted");
        }

        rejected = false;

        try {
            normalizeURL("javascript:alert(1)");
        } catch (ValidationException exception) {
            rejected = true;
        }

        if (!rejected) {
            throw new AssertionError("Unsafe URL scheme accepted");
        }

        System.out.println("Java 17 validation tests passed.");
    }

    public static void main(String[] args) {
        try {
            IOCRepository repository = new IOCRepository();

            ThreatSource networkFeed = new ThreatSource(
                "Firewall Intelligence",
                "FEED-NET-001",
                "Security Operations",
                Instant.now()
            );

            ThreatSource endpointFeed = new ThreatSource(
                "Endpoint Intelligence",
                "FEED-END-001",
                "Security Operations",
                Instant.now()
            );

            ThreatSource dnsFeed = new ThreatSource(
                "DNS Intelligence",
                "FEED-DNS-001",
                "Security Operations",
                Instant.now()
            );

            repository.register(
                new Indicator(
                    IOCType.IP,
                    "203.0.113.45",
                    networkFeed,
                    95,
                    Severity.CRITICAL,
                    Set.of("c2", "network"),
                    null
                ),
                "threat-analyst"
            );

            repository.register(
                new Indicator(
                    IOCType.DOMAIN,
                    "malware.example",
                    dnsFeed,
                    90,
                    Severity.HIGH,
                    Set.of("dns", "malware"),
                    null
                ),
                "threat-analyst"
            );

            repository.register(
                new Indicator(
                    IOCType.HASH,
                    "a".repeat(64),
                    endpointFeed,
                    99,
                    Severity.CRITICAL,
                    Set.of("sha256", "malware"),
                    null
                ),
                "threat-analyst"
            );

            repository.register(
                new Indicator(
                    IOCType.URL,
                    "https://malware.example/payload",
                    networkFeed,
                    92,
                    Severity.HIGH,
                    Set.of("payload"),
                    null
                ),
                "threat-analyst"
            );

            repository.register(
                new Indicator(
                    IOCType.FILENAME,
                    "suspicious.exe",
                    endpointFeed,
                    80,
                    Severity.MEDIUM,
                    Set.of("executable"),
                    null
                ),
                "threat-analyst"
            );

            repository.register(
                new Indicator(
                    IOCType.REGISTRY,
                    "HKEY_LOCAL_MACHINE\\Software\\BadActor\\Persistence",
                    endpointFeed,
                    90,
                    Severity.HIGH,
                    Set.of("persistence"),
                    null
                ),
                "threat-analyst"
            );

            repository.allow(
                IOCType.IP,
                "192.0.2.10",
                "security-administrator"
            );

            Policy policy = new Policy(40, 1, false);

            DetectionService detection = new DetectionService(
                repository,
                policy
            );

            String tenant = "TENANT-001";
            Instant now = Instant.now();

            List<SecurityEvent> events = List.of(
                new SecurityEvent(
                    "EVT-001", EventSource.FIREWALL,
                    IOCType.IP, "203.0.113.45",
                    "HOST-01", now, tenant
                ),
                new SecurityEvent(
                    "EVT-002", EventSource.DNS,
                    IOCType.DOMAIN, "MALWARE.EXAMPLE.",
                    "HOST-02", now, tenant
                ),
                new SecurityEvent(
                    "EVT-003", EventSource.ENDPOINT,
                    IOCType.HASH, "a".repeat(64),
                    "SERVER-01", now, tenant
                ),
                new SecurityEvent(
                    "EVT-004", EventSource.PROXY,
                    IOCType.URL, "https://malware.example/payload",
                    "HOST-03", now, tenant
                ),
                new SecurityEvent(
                    "EVT-005", EventSource.FILESYSTEM,
                    IOCType.FILENAME, "suspicious.exe",
                    "HOST-04", now, tenant
                ),
                new SecurityEvent(
                    "EVT-006", EventSource.REGISTRY,
                    IOCType.REGISTRY,
                    "HKLM\\Software\\BadActor\\Persistence",
                    "HOST-05", now, tenant
                )
            );

            List<IOCMatch> matches = detection.evaluateBatch(events);

            Investigation investigation = new Investigation(
                "CASE-2026-001",
                "Endpoint and network threat investigation",
                tenant
            );

            investigation.assign("SOC-ANALYST-01");

            for (IOCMatch match : matches) {
                investigation.addMatch(match);
            }

            if (!matches.isEmpty()) {
                investigation.transition(CaseStatus.INVESTIGATING);
                investigation.addNote(
                    "Correlated indicators require endpoint triage."
                );
            }

            RiskScoringService scoring = new RiskScoringService();

            int priority = scoring.calculate(matches);

            System.out.println("\nENTERPRISE IOC INVESTIGATION");
            System.out.println("============================");

            System.out.println(
                "Registered indicators: " + repository.activeIndicators().size()
            );

            System.out.println("Events analyzed: " + events.size());
            System.out.println("Confirmed matches: " + matches.size());

            System.out.println("Risk score: " + priority);
            System.out.println("Risk classification: " +
                scoring.classify(priority));

            for (IOCMatch match : matches) {
                System.out.printf(
                    "%s | %-8s | %-35s | %-8s | %d%%%n",
                    match.eventId(),
                    match.type(),
                    match.value(),
                    match.severity(),
                    match.confidence()
                );
            }

            System.out.println("Case: " + investigation.id());
            System.out.println("Analyst: " +
                investigation.assignedAnalyst());
            System.out.println("Case state: " + investigation.status());
            System.out.println("Audit records: " +
                repository.auditRecords().size());

            runTests();

        } catch (RuntimeException exception) {
            System.err.println(
                "Investigation failed: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
