import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/*
 * Enterprise Threat Intelligence Governance Platform
 *
 * Java 17
 *
 * Domain modeling:
 * - Intelligence classification
 * - IOC lifecycle management
 * - Threat actor and campaign relationships
 * - Feed ingestion and source provenance
 * - TLP disclosure policies
 * - Confidence and risk prioritization
 * - Observable correlation
 * - Indicator expiration and revocation
 * - Intelligence reporting
 * - Immutable domain objects
 */

public class ThreatIntelligencePlatform {

    enum IntelligenceType {
        STRATEGIC,
        OPERATIONAL,
        TACTICAL
    }

    enum IndicatorType {
        IPV4,
        DOMAIN,
        SHA256
    }

    enum Severity {
        LOW(1),
        MEDIUM(2),
        HIGH(3),
        CRITICAL(4);

        private final int weight;

        Severity(int weight) {
            this.weight = weight;
        }

        public int weight() {
            return weight;
        }
    }

    enum TLP {
        CLEAR,
        GREEN,
        AMBER,
        AMBER_STRICT,
        RED
    }

    enum IndicatorStatus {
        ACTIVE,
        EXPIRED,
        FALSE_POSITIVE,
        REVOKED
    }

    static class IntelligenceException extends RuntimeException {

        IntelligenceException(String message) {
            super(message);
        }
    }

    record ThreatActor(
        String id,
        String name,
        String motivation,
        List<String> aliases
    ) {
        ThreatActor {
            requireText(id, "Actor ID");
            requireText(name, "Actor name");
            requireText(motivation, "Motivation");
            aliases = List.copyOf(aliases);
        }
    }

    record ThreatCampaign(
        String id,
        String name,
        String actorId,
        List<String> objectives,
        List<String> targetedSectors
    ) {
        ThreatCampaign {
            requireText(id, "Campaign ID");
            requireText(name, "Campaign name");
            requireText(actorId, "Actor ID");

            objectives = List.copyOf(objectives);
            targetedSectors = List.copyOf(targetedSectors);
        }
    }

    record FeedRecord(
        String value,
        IndicatorType type,
        String source,
        int confidence,
        Severity severity,
        TLP tlp,
        IntelligenceType intelligenceType,
        Instant firstSeen,
        Instant lastSeen,
        Instant expiresAt,
        String actorId,
        String campaignId,
        Set<String> tags
    ) {
        FeedRecord {
            Objects.requireNonNull(type);
            Objects.requireNonNull(severity);
            Objects.requireNonNull(tlp);
            Objects.requireNonNull(intelligenceType);
            Objects.requireNonNull(firstSeen);
            Objects.requireNonNull(lastSeen);
            Objects.requireNonNull(expiresAt);

            tags = Set.copyOf(tags);
        }
    }

    record IndicatorView(
        String id,
        String value,
        IndicatorType type,
        String source,
        int confidence,
        Severity severity,
        TLP tlp,
        IntelligenceType intelligenceType,
        double riskScore,
        IndicatorStatus status
    ) {}

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IntelligenceException(
                field + " cannot be empty."
            );
        }
    }

    static final class Indicator {

        private final String id;
        private final String value;
        private final IndicatorType type;
        private final String source;
        private final TLP tlp;
        private final IntelligenceType intelligenceType;
        private final Instant firstSeen;
        private final String actorId;
        private final String campaignId;

        private int confidence;
        private Severity severity;
        private Instant lastSeen;
        private Instant expiresAt;
        private final Set<String> tags = new HashSet<>();
        private final Set<String> references = new HashSet<>();

        private IndicatorStatus status = IndicatorStatus.ACTIVE;

        Indicator(FeedRecord record) {

            this.value = normalize(
                record.value(),
                record.type()
            );

            this.id = record.type() + ":" + this.value;

            requireText(record.source(), "Feed source");

            if (
                record.confidence() < 0 ||
                record.confidence() > 100
            ) {
                throw new IntelligenceException(
                    "Confidence must be between 0 and 100."
                );
            }

            if (record.lastSeen().isBefore(record.firstSeen())) {
                throw new IntelligenceException(
                    "lastSeen cannot precede firstSeen."
                );
            }

            if (!record.expiresAt().isAfter(record.firstSeen())) {
                throw new IntelligenceException(
                    "Expiration must follow firstSeen."
                );
            }

            this.type = record.type();
            this.source = record.source();
            this.confidence = record.confidence();
            this.severity = record.severity();
            this.tlp = record.tlp();
            this.intelligenceType = record.intelligenceType();
            this.firstSeen = record.firstSeen();
            this.lastSeen = record.lastSeen();
            this.expiresAt = record.expiresAt();
            this.actorId = record.actorId();
            this.campaignId = record.campaignId();

            this.tags.addAll(record.tags());
            this.references.add(record.source());
        }

        private void merge(Indicator incoming) {

            confidence = Math.max(
                confidence,
                incoming.confidence
            );

            if (incoming.severity.weight() > severity.weight()) {
                severity = incoming.severity;
            }

            if (incoming.lastSeen.isAfter(lastSeen)) {
                lastSeen = incoming.lastSeen;
            }

            if (incoming.expiresAt.isAfter(expiresAt)) {
                expiresAt = incoming.expiresAt;
            }

            tags.addAll(incoming.tags);
            references.addAll(incoming.references);
        }

        boolean isActive(Instant now) {
            return status == IndicatorStatus.ACTIVE
                && now.isBefore(expiresAt);
        }

        double riskScore(Instant now) {

            if (!isActive(now)) {
                return 0;
            }

            double ageHours = Math.max(
                0,
                Duration.between(lastSeen, now).toMinutes() / 60.0
            );

            double recency = Math.max(
                0,
                100 - ageHours / 24 * 5
            );

            return Math.min(
                100,
                confidence * 0.4
                + severity.weight() * 25 * 0.4
                + recency * 0.2
            );
        }

        IndicatorView view(Instant now) {

            return new IndicatorView(
                id,
                value,
                type,
                source,
                confidence,
                severity,
                tlp,
                intelligenceType,
                riskScore(now),
                status
            );
        }

        void updateStatus(IndicatorStatus newStatus) {
            status = Objects.requireNonNull(newStatus);
        }
    }

    static final class IndicatorNormalizer {

        private static final Pattern IPV4 = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$"
        );

        private static final Pattern SHA256 = Pattern.compile(
            "^[a-fA-F0-9]{64}$"
        );

        private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)(?:[a-zA-Z0-9]"
            + "(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+"
            + "[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        );

        static String normalize(
            String value,
            IndicatorType type
        ) {

            requireText(value, "Indicator");

            if (value.length() > 2048) {
                throw new IntelligenceException(
                    "Indicator exceeds maximum length."
                );
            }

            value = value.trim();

            switch (type) {

                case IPV4 -> {

                    if (!IPV4.matcher(value).matches()) {
                        throw new IntelligenceException(
                            "Invalid IPv4 address."
                        );
                    }

                    String[] parts = value.split("\\.");

                    StringBuilder normalized = new StringBuilder();

                    for (String part : parts) {

                        int octet;

                        try {
                            octet = Integer.parseInt(part);
                        } catch (NumberFormatException exception) {
                            throw new IntelligenceException(
                                "Invalid IPv4 octet."
                            );
                        }

                        if (octet > 255) {
                            throw new IntelligenceException(
                                "IPv4 octet exceeds 255."
                            );
                        }

                        if (normalized.length() > 0) {
                            normalized.append(".");
                        }

                        normalized.append(octet);
                    }

                    return normalized.toString();
                }

                case DOMAIN -> {

                    String domain = value
                        .replaceAll("\\.$", "")
                        .toLowerCase(Locale.ROOT);

                    if (!DOMAIN.matcher(domain).matches()) {
                        throw new IntelligenceException(
                            "Invalid domain."
                        );
                    }

                    return domain;
                }

                case SHA256 -> {

                    if (!SHA256.matcher(value).matches()) {
                        throw new IntelligenceException(
                            "Invalid SHA-256 hash."
                        );
                    }

                    return value.toLowerCase(Locale.ROOT);
                }
            }

            throw new IntelligenceException(
                "Unsupported indicator type."
            );
        }
    }

    static final class SharingPolicy {

        private static final Map<TLP, Set<String>> RULES = Map.of(
            TLP.CLEAR,
            Set.of(
                "public",
                "community",
                "organization",
                "designated_group",
                "internal"
            ),

            TLP.GREEN,
            Set.of(
                "community",
                "organization",
                "designated_group",
                "internal"
            ),

            TLP.AMBER,
            Set.of(
                "organization",
                "designated_group",
                "internal"
            ),

            TLP.AMBER_STRICT,
            Set.of(
                "designated_group",
                "internal"
            ),

            TLP.RED,
            Set.of()
        );

        static boolean canShare(
            TLP classification,
            String recipient
        ) {
            return RULES.get(classification).contains(recipient);
        }
    }

    interface FeedProvider {
        List<FeedRecord> fetch() throws Exception;
        String name();
    }

    static final class ThreatIntelligenceService {

        private final Map<String, ThreatActor> actors =
            new HashMap<>();

        private final Map<String, ThreatCampaign> campaigns =
            new HashMap<>();

        private final Map<String, Indicator> indicators =
            new HashMap<>();

        private final Map<String, Integer> feedFailures =
            new HashMap<>();

        public void registerActor(ThreatActor actor) {

            if (actors.putIfAbsent(actor.id(), actor) != null) {
                throw new IntelligenceException(
                    "Threat actor already exists."
                );
            }
        }

        public void registerCampaign(ThreatCampaign campaign) {

            if (!actors.containsKey(campaign.actorId())) {
                throw new IntelligenceException(
                    "Campaign references an unknown actor."
                );
            }

            if (
                campaigns.putIfAbsent(
                    campaign.id(),
                    campaign
                ) != null
            ) {
                throw new IntelligenceException(
                    "Campaign already exists."
                );
            }
        }

        public String ingest(FeedRecord record) {

            Indicator indicator = new Indicator(record);

            if (
                indicator.actorId != null &&
                !indicator.actorId.isBlank() &&
                !actors.containsKey(indicator.actorId)
            ) {
                throw new IntelligenceException(
                    "Unknown threat actor."
                );
            }

            if (
                indicator.campaignId != null &&
                !indicator.campaignId.isBlank() &&
                !campaigns.containsKey(indicator.campaignId)
            ) {
                throw new IntelligenceException(
                    "Unknown campaign."
                );
            }

            Indicator existing = indicators.get(indicator.id);

            if (existing != null) {
                existing.merge(indicator);
                return existing.id;
            }

            indicators.put(indicator.id, indicator);

            return indicator.id;
        }

        public Map<String, Object> ingestFeed(
            FeedProvider provider
        ) {

            List<String> accepted = new ArrayList<>();
            List<String> rejected = new ArrayList<>();

            try {

                for (FeedRecord record : provider.fetch()) {

                    try {
                        accepted.add(ingest(record));
                    } catch (RuntimeException exception) {
                        rejected.add(exception.getMessage());
                    }
                }

            } catch (Exception exception) {

                feedFailures.merge(
                    provider.name(),
                    1,
                    Integer::sum
                );

                return Map.of(
                    "feed",
                    provider.name(),
                    "accepted",
                    accepted,
                    "rejected",
                    rejected,
                    "failure",
                    exception.getMessage()
                );
            }

            return Map.of(
                "feed",
                provider.name(),
                "accepted",
                accepted,
                "rejected",
                rejected
            );
        }

        public List<IndicatorView> search(
            IndicatorType type,
            IntelligenceType intelligenceType,
            String tag
        ) {

            Instant now = Instant.now();

            return indicators.values()
                .stream()
                .filter(item -> item.isActive(now))
                .filter(item ->
                    type == null || item.type == type
                )
                .filter(item ->
                    intelligenceType == null ||
                    item.intelligenceType == intelligenceType
                )
                .filter(item ->
                    tag == null || item.tags.contains(tag)
                )
                .sorted(
                    Comparator.comparingDouble(
                        (Indicator item) -> item.riskScore(now)
                    ).reversed()
                )
                .map(item -> item.view(now))
                .collect(Collectors.toList());
        }

        public List<IndicatorView> correlateCampaign(
            String campaignId
        ) {

            if (!campaigns.containsKey(campaignId)) {
                throw new IntelligenceException(
                    "Unknown campaign."
                );
            }

            Instant now = Instant.now();

            return indicators.values()
                .stream()
                .filter(item ->
                    campaignId.equals(item.campaignId)
                )
                .filter(item -> item.isActive(now))
                .map(item -> item.view(now))
                .toList();
        }

        public List<IndicatorView> evaluateObservable(
            String value,
            IndicatorType type
        ) {

            String normalized = IndicatorNormalizer.normalize(
                value,
                type
            );

            return search(type, null, null)
                .stream()
                .filter(item -> item.value().equals(normalized))
                .toList();
        }

        public void updateStatus(
            String id,
            IndicatorStatus status
        ) {

            Indicator indicator = indicators.get(id);

            if (indicator == null) {
                throw new IntelligenceException(
                    "Indicator not found."
                );
            }

            indicator.updateStatus(status);
        }

        public int expireIndicators() {

            Instant now = Instant.now();
            int count = 0;

            for (Indicator indicator : indicators.values()) {

                if (
                    indicator.status == IndicatorStatus.ACTIVE &&
                    !now.isBefore(indicator.expiresAt)
                ) {
                    indicator.updateStatus(
                        IndicatorStatus.EXPIRED
                    );

                    count++;
                }
            }

            return count;
        }

        public Map<String, Object> report() {

            List<IndicatorView> active = search(
                null,
                null,
                null
            );

            Map<String, Long> intelligenceCounts =
                active.stream().collect(
                    Collectors.groupingBy(
                        item -> item.intelligenceType().name(),
                        Collectors.counting()
                    )
                );

            Map<String, Long> severityCounts =
                active.stream().collect(
                    Collectors.groupingBy(
                        item -> item.severity().name(),
                        Collectors.counting()
                    )
                );

            return Map.of(
                "generatedAt",
                Instant.now().toString(),
                "totalIndicators",
                indicators.size(),
                "activeIndicators",
                active.size(),
                "actors",
                actors.size(),
                "campaigns",
                campaigns.size(),
                "intelligenceDistribution",
                intelligenceCounts,
                "severityDistribution",
                severityCounts,
                "feedFailures",
                Collections.unmodifiableMap(feedFailures),
                "highestPriority",
                active.stream().limit(10).toList()
            );
        }
    }

    private static FeedRecord sample(
        String value,
        IndicatorType type,
        String source,
        int confidence,
        Severity severity,
        TLP tlp,
        IntelligenceType intelligenceType,
        String actor,
        String campaign,
        Set<String> tags
    ) {

        Instant now = Instant.now();

        return new FeedRecord(
            value,
            type,
            source,
            confidence,
            severity,
            tlp,
            intelligenceType,
            now,
            now,
            now.plus(Duration.ofDays(30)),
            actor,
            campaign,
            tags
        );
    }

    public static void main(String[] args) {

        ThreatIntelligenceService service =
            new ThreatIntelligenceService();

        service.registerActor(
            new ThreatActor(
                "ACT-001",
                "Example APT",
                "Espionage",
                List.of("EXAMPLE-APT")
            )
        );

        service.registerCampaign(
            new ThreatCampaign(
                "CMP-001",
                "Northern Gateway",
                "ACT-001",
                List.of(
                    "Credential theft",
                    "Data exfiltration"
                ),
                List.of("Government", "Energy")
            )
        );

        FeedProvider provider = new FeedProvider() {

            @Override
            public String name() {
                return "Example-TI-Feed";
            }

            @Override
            public List<FeedRecord> fetch() {

                return List.of(
                    sample(
                        "203.0.113.25",
                        IndicatorType.IPV4,
                        name(),
                        95,
                        Severity.CRITICAL,
                        TLP.AMBER,
                        IntelligenceType.TACTICAL,
                        "ACT-001",
                        "CMP-001",
                        Set.of("c2", "malware")
                    ),

                    sample(
                        "malicious-example.org",
                        IndicatorType.DOMAIN,
                        name(),
                        85,
                        Severity.HIGH,
                        TLP.GREEN,
                        IntelligenceType.OPERATIONAL,
                        "ACT-001",
                        "CMP-001",
                        Set.of("phishing")
                    )
                );
            }
        };

        Map<String, Object> ingestion =
            service.ingestFeed(provider);

        System.out.println("FEED INGESTION");
        System.out.println(ingestion);

        System.out.println("\nTACTICAL INTELLIGENCE");

        service.search(
            null,
            IntelligenceType.TACTICAL,
            null
        ).forEach(System.out::println);

        System.out.println("\nCAMPAIGN CORRELATION");

        service.correlateCampaign("CMP-001")
            .forEach(System.out::println);

        System.out.println("\nOBSERVABLE EVALUATION");

        service.evaluateObservable(
            "203.0.113.25",
            IndicatorType.IPV4
        ).forEach(System.out::println);

        System.out.println("\nTLP POLICY");

        System.out.println(
            SharingPolicy.canShare(
                TLP.AMBER,
                "organization"
            )
        );

        System.out.println(
            SharingPolicy.canShare(
                TLP.RED,
                "public"
            )
        );

        System.out.println("\nINTELLIGENCE REPORT");

        service.report().forEach(
            (key, value) ->
                System.out.println(key + ": " + value)
        );

        System.out.println("\nEXPIRATION PROCESS");

        System.out.println(
            "Expired indicators: " +
            service.expireIndicators()
        );

        System.out.println("\nVALIDATION FAILURE");

        try {

            IndicatorNormalizer.normalize(
                "999.999.999.999",
                IndicatorType.IPV4
            );

        } catch (IntelligenceException exception) {

            System.out.println(
                "Rejected: " + exception.getMessage()
            );
        }
    }
}
