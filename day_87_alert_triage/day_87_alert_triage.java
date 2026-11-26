import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/*
 * ENTERPRISE SECURITY ALERT TRIAGE PLATFORM
 *
 * Runtime: Java 17
 * Dependencies: Java standard library only.
 *
 * Enterprise capabilities:
 * - Typed security alert domain.
 * - Severity and confidence assessment.
 * - Contextual asset and threat enrichment.
 * - Evidence-based classification.
 * - Configurable risk scoring.
 * - Role-based analyst assignment.
 * - Analyst workload controls.
 * - Investigation state transitions.
 * - Escalation and resolution.
 * - Immutable audit records.
 * - Operational reporting.
 */

public class AlertTriageEnterprise {

    // ========================================================
    // ENUMERATIONS
    // ========================================================

    enum Severity {
        CRITICAL(1.00),
        HIGH(0.80),
        MEDIUM(0.55),
        LOW(0.30),
        INFORMATIONAL(0.10);

        private final double weight;

        Severity(double weight) {
            this.weight = weight;
        }

        public double weight() {
            return weight;
        }
    }

    enum AlertStatus {
        NEW,
        ENRICHING,
        TRIAGED,
        ASSIGNED,
        INVESTIGATING,
        ESCALATED,
        RESOLVED,
        CLOSED
    }

    enum Verdict {
        TRUE_POSITIVE,
        FALSE_POSITIVE,
        BENIGN_TRUE_POSITIVE,
        UNDETERMINED
    }

    enum EvidenceType {
        MALWARE_DETECTION,
        CONFIRMED_C2,
        UNAUTHORIZED_ACCESS,
        APPROVED_ACTIVITY,
        AUTHORIZED_SCANNER,
        MAINTENANCE_WINDOW,
        OTHER
    }

    enum AnalystTier {
        L1(1),
        L2(2),
        L3(3);

        private final int level;

        AnalystTier(int level) {
            this.level = level;
        }

        public int level() {
            return level;
        }
    }

    // ========================================================
    // EXCEPTIONS
    // ========================================================

    static class DomainException extends RuntimeException {
        DomainException(String message) {
            super(message);
        }
    }

    static class AuthorizationException extends RuntimeException {
        AuthorizationException(String message) {
            super(message);
        }
    }

    static class CapacityException extends RuntimeException {
        CapacityException(String message) {
            super(message);
        }
    }

    // ========================================================
    // VALIDATION
    // ========================================================

    static final class Validation {

        private Validation() {}

        static void text(String value, String field) {
            if (value == null || value.isBlank()) {
                throw new DomainException(
                    field + " must not be empty"
                );
            }
        }

        static void probability(double value, String field) {
            if (
                !Double.isFinite(value)
                || value < 0.0
                || value > 1.0
            ) {
                throw new DomainException(
                    field + " must be between 0 and 1"
                );
            }
        }

        static void positive(int value, String field) {
            if (value < 1) {
                throw new DomainException(
                    field + " must be positive"
                );
            }
        }
    }

    // ========================================================
    // IMMUTABLE DOMAIN RECORDS
    // ========================================================

    record Evidence(
        EvidenceType type,
        String description,
        String source,
        double reliability,
        Instant observedAt
    ) {
        Evidence {
            if (type == null || observedAt == null) {
                throw new DomainException(
                    "Evidence type and timestamp are required"
                );
            }

            Validation.text(description, "Evidence description");
            Validation.text(source, "Evidence source");

            Validation.probability(
                reliability,
                "Evidence reliability"
            );
        }
    }

    record Enrichment(
        double assetCriticality,
        double threatScore,
        boolean maliciousIndicator,
        boolean privilegedAsset,
        int historicalAlerts,
        String assetOwner,
        String businessContext
    ) {
        Enrichment {
            Validation.probability(
                assetCriticality,
                "Asset criticality"
            );

            Validation.probability(
                threatScore,
                "Threat score"
            );

            if (historicalAlerts < 0) {
                throw new DomainException(
                    "Historical alert count cannot be negative"
                );
            }

            Validation.text(assetOwner, "Asset owner");
            Validation.text(businessContext, "Business context");
        }
    }

    record AuditEvent(
        UUID eventId,
        Instant timestamp,
        String action,
        String actor,
        Map<String, String> details
    ) {
        AuditEvent {
            details = Map.copyOf(details);
        }
    }

    // ========================================================
    // POLICY OBJECT
    // ========================================================

    record TriagePolicy(
        double criticalThreshold,
        double highThreshold,
        double mediumThreshold,
        double maliciousEvidenceThreshold,
        double benignEvidenceThreshold,
        int minimumTierForCritical
    ) {
        TriagePolicy {
            Validation.probability(
                criticalThreshold,
                "Critical threshold"
            );

            Validation.probability(
                highThreshold,
                "High threshold"
            );

            Validation.probability(
                mediumThreshold,
                "Medium threshold"
            );

            Validation.probability(
                maliciousEvidenceThreshold,
                "Malicious evidence threshold"
            );

            Validation.probability(
                benignEvidenceThreshold,
                "Benign evidence threshold"
            );

            if (
                criticalThreshold < highThreshold
                || highThreshold < mediumThreshold
            ) {
                throw new DomainException(
                    "Risk thresholds must be descending"
                );
            }

            if (
                minimumTierForCritical < 1
                || minimumTierForCritical > 3
            ) {
                throw new DomainException(
                    "Invalid critical analyst tier"
                );
            }
        }

        static TriagePolicy standard() {
            return new TriagePolicy(
                0.85,
                0.70,
                0.45,
                0.70,
                0.90,
                3
            );
        }
    }

    // ========================================================
    // SECURITY ALERT AGGREGATE
    // ========================================================

    static class SecurityAlert {

        private final String id;
        private final String title;
        private final String description;
        private final String source;
        private final String category;
        private final String assetId;
        private final Severity severity;
        private final double confidence;
        private final Instant observedAt;

        private AlertStatus status = AlertStatus.NEW;

        private Verdict verdict = Verdict.UNDETERMINED;

        private Enrichment enrichment;

        private double riskScore;

        private String assignedAnalyst;

        private final List<Evidence> evidence =
            new ArrayList<>();

        private final List<String> findings =
            new ArrayList<>();

        private final List<AuditEvent> audit =
            new ArrayList<>();

        SecurityAlert(
            String id,
            String title,
            String description,
            String source,
            String category,
            String assetId,
            Severity severity,
            double confidence,
            Instant observedAt
        ) {
            Validation.text(id, "Alert ID");
            Validation.text(title, "Alert title");
            Validation.text(source, "Alert source");
            Validation.text(category, "Alert category");
            Validation.text(assetId, "Asset ID");

            Validation.probability(
                confidence,
                "Detection confidence"
            );

            if (
                severity == null
                || observedAt == null
            ) {
                throw new DomainException(
                    "Severity and observed time are required"
                );
            }

            this.id = id;
            this.title = title;
            this.description = description;
            this.source = source;
            this.category = category;
            this.assetId = assetId;
            this.severity = severity;
            this.confidence = confidence;
            this.observedAt = observedAt;
        }

        void addEvidence(Evidence item) {
            if (
                status == AlertStatus.CLOSED
                || status == AlertStatus.RESOLVED
            ) {
                throw new DomainException(
                    "Cannot add evidence to a completed alert"
                );
            }

            evidence.add(item);
        }

        void addFinding(String finding) {
            Validation.text(finding, "Finding");
            findings.add(finding);
        }

        void record(
            String action,
            String actor,
            Map<String, String> details
        ) {
            audit.add(
                new AuditEvent(
                    UUID.randomUUID(),
                    Instant.now(),
                    action,
                    actor,
                    details
                )
            );
        }

        public String id() {
            return id;
        }

        public String assetId() {
            return assetId;
        }

        public Severity severity() {
            return severity;
        }

        public double confidence() {
            return confidence;
        }

        public AlertStatus status() {
            return status;
        }

        public Verdict verdict() {
            return verdict;
        }

        public double riskScore() {
            return riskScore;
        }

        public String assignedAnalyst() {
            return assignedAnalyst;
        }

        public List<AuditEvent> audit() {
            return List.copyOf(audit);
        }

        public List<String> findings() {
            return List.copyOf(findings);
        }

        public List<Evidence> evidence() {
            return List.copyOf(evidence);
        }
    }

    // ========================================================
    // ANALYST DOMAIN
    // ========================================================

    static class Analyst {

        private final String id;
        private final String name;
        private final AnalystTier tier;
        private final int capacity;

        private final Set<String> specialties;

        private final Set<String> activeAlerts =
            new HashSet<>();

        Analyst(
            String id,
            String name,
            AnalystTier tier,
            int capacity,
            Set<String> specialties
        ) {
            Validation.text(id, "Analyst ID");
            Validation.text(name, "Analyst name");
            Validation.positive(capacity, "Analyst capacity");

            if (tier == null) {
                throw new DomainException("Analyst tier is required");
            }

            this.id = id;
            this.name = name;
            this.tier = tier;
            this.capacity = capacity;
            this.specialties = Set.copyOf(specialties);
        }

        boolean available() {
            return activeAlerts.size() < capacity;
        }

        double utilization() {
            return (double) activeAlerts.size() / capacity;
        }
    }

    // ========================================================
    // RISK SCORING SERVICE
    // ========================================================

    static class RiskScoringService {

        double calculate(
            SecurityAlert alert,
            Enrichment enrichment
        ) {
            double score =
                0.30 * alert.severity.weight()
                + 0.25 * alert.confidence
                + 0.20 * enrichment.threatScore()
                + 0.25 * enrichment.assetCriticality();

            if (enrichment.privilegedAsset()) {
                score += 0.10;
            }

            if (enrichment.maliciousIndicator()) {
                score += 0.15;
            }

            score += Math.min(
                enrichment.historicalAlerts() * 0.01,
                0.10
            );

            return Math.min(
                1.0,
                Math.round(score * 10000.0) / 10000.0
            );
        }

        int requiredTier(
            double score,
            TriagePolicy policy
        ) {
            if (score >= policy.criticalThreshold()) {
                return policy.minimumTierForCritical();
            }

            if (score >= policy.highThreshold()) {
                return 2;
            }

            return 1;
        }

        String priority(
            double score,
            TriagePolicy policy
        ) {
            if (score >= policy.criticalThreshold()) return "P1";
            if (score >= policy.highThreshold()) return "P2";
            if (score >= policy.mediumThreshold()) return "P3";
            return "P4";
        }
    }

    // ========================================================
    // EVIDENCE CLASSIFICATION SERVICE
    // ========================================================

    static class EvidenceEvaluationService {

        private final TriagePolicy policy;

        EvidenceEvaluationService(TriagePolicy policy) {
            this.policy = policy;
        }

        Verdict evaluate(
            SecurityAlert alert,
            Enrichment enrichment
        ) {
            boolean malicious = alert.evidence().stream()
                .anyMatch(evidence ->
                    switch (evidence.type()) {
                        case MALWARE_DETECTION,
                             CONFIRMED_C2,
                             UNAUTHORIZED_ACCESS ->
                            evidence.reliability()
                                >= policy.maliciousEvidenceThreshold();

                        default -> false;
                    }
                );

            boolean benign = alert.evidence().stream()
                .anyMatch(evidence ->
                    switch (evidence.type()) {
                        case APPROVED_ACTIVITY,
                             AUTHORIZED_SCANNER,
                             MAINTENANCE_WINDOW ->
                            evidence.reliability()
                                >= policy.benignEvidenceThreshold();

                        default -> false;
                    }
                );

            if (malicious) {
                return Verdict.TRUE_POSITIVE;
            }

            if (benign) {
                return Verdict.FALSE_POSITIVE;
            }

            if (
                alert.confidence() >= 0.90
                && enrichment.maliciousIndicator()
            ) {
                return Verdict.TRUE_POSITIVE;
            }

            return Verdict.UNDETERMINED;
        }
    }

    // ========================================================
    // STATE TRANSITION POLICY
    // ========================================================

    static class WorkflowPolicy {

        private static final Map<AlertStatus, Set<AlertStatus>>
            TRANSITIONS = Map.of(
                AlertStatus.NEW,
                Set.of(AlertStatus.ENRICHING, AlertStatus.CLOSED),

                AlertStatus.ENRICHING,
                Set.of(AlertStatus.TRIAGED, AlertStatus.ESCALATED),

                AlertStatus.TRIAGED,
                Set.of(
                    AlertStatus.ASSIGNED,
                    AlertStatus.ESCALATED,
                    AlertStatus.CLOSED
                ),

                AlertStatus.ASSIGNED,
                Set.of(
                    AlertStatus.INVESTIGATING,
                    AlertStatus.ESCALATED
                ),

                AlertStatus.INVESTIGATING,
                Set.of(
                    AlertStatus.ESCALATED,
                    AlertStatus.RESOLVED
                ),

                AlertStatus.ESCALATED,
                Set.of(
                    AlertStatus.INVESTIGATING,
                    AlertStatus.RESOLVED
                ),

                AlertStatus.RESOLVED,
                Set.of(AlertStatus.CLOSED),

                AlertStatus.CLOSED,
                Set.of()
            );

        void transition(
            SecurityAlert alert,
            AlertStatus next,
            String actor
        ) {
            if (!TRANSITIONS.get(alert.status).contains(next)) {
                throw new DomainException(
                    "Invalid transition: "
                    + alert.status
                    + " -> "
                    + next
                );
            }

            AlertStatus previous = alert.status;
            alert.status = next;

            alert.record(
                "status_transition",
                actor,
                Map.of(
                    "previous", previous.name(),
                    "current", next.name()
                )
            );
        }
    }

    // ========================================================
    // ENTERPRISE ASSIGNMENT SERVICE
    // ========================================================

    static class AnalystAssignmentService {

        private final RiskScoringService riskService;
        private final TriagePolicy policy;

        AnalystAssignmentService(
            RiskScoringService riskService,
            TriagePolicy policy
        ) {
            this.riskService = riskService;
            this.policy = policy;
        }

        Analyst assign(
            SecurityAlert alert,
            List<Analyst> analysts
        ) {
            if (alert.status != AlertStatus.TRIAGED) {
                throw new DomainException(
                    "Alert must be triaged before assignment"
                );
            }

            if (alert.verdict == Verdict.FALSE_POSITIVE) {
                throw new DomainException(
                    "False positives cannot be assigned"
                );
            }

            int required = riskService.requiredTier(
                alert.riskScore,
                policy
            );

            Optional<Analyst> candidate = analysts.stream()
                .filter(Analyst::available)
                .filter(a -> a.tier.level() >= required)
                .min(
                    Comparator
                        .comparingDouble(Analyst::utilization)
                        .thenComparingInt(a -> a.tier.level())
                );

            Analyst analyst = candidate.orElseThrow(
                () -> new CapacityException(
                    "No eligible analyst is available"
                )
            );

            analyst.activeAlerts.add(alert.id);

            alert.assignedAnalyst = analyst.id;

            return analyst;
        }

        void release(
            SecurityAlert alert,
            List<Analyst> analysts
        ) {
            if (alert.assignedAnalyst == null) {
                return;
            }

            analysts.stream()
                .filter(a -> a.id.equals(alert.assignedAnalyst))
                .findFirst()
                .ifPresent(
                    analyst -> analyst.activeAlerts.remove(alert.id)
                );
        }
    }

    // ========================================================
    // ENTERPRISE TRIAGE APPLICATION SERVICE
    // ========================================================

    static class AlertTriageService {

        private final Map<String, SecurityAlert> alerts =
            new HashMap<>();

        private final List<Analyst> analysts;

        private final RiskScoringService riskService =
            new RiskScoringService();

        private final TriagePolicy policy;

        private final EvidenceEvaluationService evidenceService;

        private final WorkflowPolicy workflowPolicy =
            new WorkflowPolicy();

        private final AnalystAssignmentService assignmentService;

        AlertTriageService(
            List<Analyst> analysts,
            TriagePolicy policy
        ) {
            this.analysts = new ArrayList<>(analysts);
            this.policy = policy;

            this.evidenceService =
                new EvidenceEvaluationService(policy);

            this.assignmentService =
                new AnalystAssignmentService(
                    riskService,
                    policy
                );
        }

        void ingest(SecurityAlert alert) {
            if (alerts.putIfAbsent(alert.id(), alert) != null) {
                throw new DomainException(
                    "Duplicate alert identifier"
                );
            }

            alert.record(
                "ingested",
                "ingestion_service",
                Map.of("source", "security_monitoring")
            );
        }

        SecurityAlert get(String id) {
            SecurityAlert alert = alerts.get(id);

            if (alert == null) {
                throw new DomainException("Alert not found: " + id);
            }

            return alert;
        }

        void enrich(
            String alertId,
            Enrichment enrichment
        ) {
            SecurityAlert alert = get(alertId);

            workflowPolicy.transition(
                alert,
                AlertStatus.ENRICHING,
                "enrichment_service"
            );

            alert.enrichment = enrichment;

            alert.record(
                "enriched",
                "enrichment_service",
                Map.of(
                    "owner", enrichment.assetOwner(),
                    "business_context", enrichment.businessContext()
                )
            );
        }

        void triage(String alertId) {
            SecurityAlert alert = get(alertId);

            if (alert.status != AlertStatus.ENRICHING) {
                throw new DomainException(
                    "Enrichment is required before triage"
                );
            }

            alert.riskScore = riskService.calculate(
                alert,
                alert.enrichment
            );

            alert.verdict = evidenceService.evaluate(
                alert,
                alert.enrichment
            );

            workflowPolicy.transition(
                alert,
                AlertStatus.TRIAGED,
                "triage_engine"
            );

            alert.record(
                "triage_completed",
                "triage_engine",
                Map.of(
                    "risk", Double.toString(alert.riskScore),
                    "priority", riskService.priority(
                        alert.riskScore,
                        policy
                    ),
                    "verdict", alert.verdict.name()
                )
            );
        }

        Analyst assign(String alertId) {
            SecurityAlert alert = get(alertId);

            Analyst analyst = assignmentService.assign(
                alert,
                analysts
            );

            workflowPolicy.transition(
                alert,
                AlertStatus.ASSIGNED,
                "assignment_service"
            );

            alert.record(
                "assigned",
                "assignment_service",
                Map.of("analyst_id", analyst.id)
            );

            return analyst;
        }

        void investigate(
            String alertId,
            String analystId,
            String finding,
            Evidence evidence
        ) {
            SecurityAlert alert = get(alertId);

            if (
                alert.assignedAnalyst == null
                || !alert.assignedAnalyst.equals(analystId)
            ) {
                throw new AuthorizationException(
                    "Assigned analyst authorization required"
                );
            }

            if (
                alert.status != AlertStatus.ASSIGNED
                && alert.status != AlertStatus.INVESTIGATING
            ) {
                throw new DomainException(
                    "Alert cannot enter investigation"
                );
            }

            if (alert.status == AlertStatus.ASSIGNED) {
                workflowPolicy.transition(
                    alert,
                    AlertStatus.INVESTIGATING,
                    analystId
                );
            }

            alert.addFinding(finding);

            if (evidence != null) {
                alert.addEvidence(evidence);
            }

            alert.verdict = evidenceService.evaluate(
                alert,
                alert.enrichment
            );

            alert.record(
                "investigation_update",
                analystId,
                Map.of("finding", finding)
            );
        }

        void escalate(
            String alertId,
            String actor,
            String reason
        ) {
            SecurityAlert alert = get(alertId);

            Validation.text(reason, "Escalation reason");

            workflowPolicy.transition(
                alert,
                AlertStatus.ESCALATED,
                actor
            );

            alert.record(
                "escalated",
                actor,
                Map.of("reason", reason)
            );
        }

        void resolve(
            String alertId,
            String actor,
            Verdict verdict,
            String findings
        ) {
            SecurityAlert alert = get(alertId);

            if (
                alert.status != AlertStatus.INVESTIGATING
                && alert.status != AlertStatus.ESCALATED
            ) {
                throw new DomainException(
                    "Alert must be under investigation"
                );
            }

            if (
                verdict == null
                || verdict == Verdict.UNDETERMINED
            ) {
                throw new DomainException(
                    "A conclusive verdict is required"
                );
            }

            Validation.text(findings, "Resolution findings");

            alert.verdict = verdict;
            alert.addFinding(findings);

            workflowPolicy.transition(
                alert,
                AlertStatus.RESOLVED,
                actor
            );

            alert.record(
                "resolved",
                actor,
                Map.of("verdict", verdict.name())
            );

            assignmentService.release(
                alert,
                analysts
            );
        }

        void close(String alertId, String actor) {
            SecurityAlert alert = get(alertId);

            workflowPolicy.transition(
                alert,
                AlertStatus.CLOSED,
                actor
            );

            alert.record(
                "closed",
                actor,
                Map.of()
            );
        }

        List<SecurityAlert> allAlerts() {
            return List.copyOf(alerts.values());
        }

        List<Analyst> allAnalysts() {
            return List.copyOf(analysts);
        }
    }

    // ========================================================
    // REPORTING
    // ========================================================

    static class AlertReportService {

        void print(List<SecurityAlert> alerts) {

            Map<String, Long> statusCounts =
                alerts.stream().collect(
                    Collectors.groupingBy(
                        a -> a.status.name(),
                        Collectors.counting()
                    )
                );

            Map<String, Long> verdictCounts =
                alerts.stream().collect(
                    Collectors.groupingBy(
                        a -> a.verdict.name(),
                        Collectors.counting()
                    )
                );

            Map<String, Long> severityCounts =
                alerts.stream().collect(
                    Collectors.groupingBy(
                        a -> a.severity.name(),
                        Collectors.counting()
                    )
                );

            double averageConfidence = alerts.stream()
                .mapToDouble(a -> a.confidence)
                .average()
                .orElse(0.0);

            double averageRisk = alerts.stream()
                .mapToDouble(a -> a.riskScore)
                .average()
                .orElse(0.0);

            long falsePositives = alerts.stream()
                .filter(
                    a -> a.verdict == Verdict.FALSE_POSITIVE
                )
                .count();

            double falsePositiveRate = alerts.isEmpty()
                ? 0.0
                : (double) falsePositives / alerts.size();

            System.out.println("\nENTERPRISE ALERT REPORT");

            System.out.println("Total alerts: " + alerts.size());

            System.out.println(
                "Average confidence: " + averageConfidence
            );

            System.out.println(
                "Average risk: " + averageRisk
            );

            System.out.println(
                "False-positive rate: " + falsePositiveRate
            );

            System.out.println("Status: " + statusCounts);
            System.out.println("Verdicts: " + verdictCounts);
            System.out.println("Severity: " + severityCounts);

            System.out.println("\nALERT AUDIT");

            alerts.forEach(alert ->
                System.out.printf(
                    "%s | %s | %s | Audit events: %d%n",
                    alert.id(),
                    alert.status(),
                    alert.verdict(),
                    alert.audit().size()
                )
            );
        }
    }

    // ========================================================
    // EXECUTABLE ENTERPRISE SCENARIO
    // ========================================================

    public static void main(String[] args) {

        try {

            TriagePolicy policy = TriagePolicy.standard();

            List<Analyst> analysts = List.of(
                new Analyst(
                    "AN-01",
                    "Analyst One",
                    AnalystTier.L1,
                    4,
                    Set.of("authentication")
                ),
                new Analyst(
                    "AN-02",
                    "Analyst Two",
                    AnalystTier.L2,
                    5,
                    Set.of("network", "endpoint")
                ),
                new Analyst(
                    "AN-03",
                    "Analyst Three",
                    AnalystTier.L3,
                    5,
                    Set.of("identity", "forensics")
                )
            );

            AlertTriageService service =
                new AlertTriageService(analysts, policy);

            SecurityAlert first = new SecurityAlert(
                "ALT-4001",
                "Suspicious privileged login",
                "Administrator login from unusual location",
                "SIEM",
                "identity",
                "SRV-001",
                Severity.CRITICAL,
                0.96,
                Instant.now()
            );

            first.addEvidence(
                new Evidence(
                    EvidenceType.UNAUTHORIZED_ACCESS,
                    "Unapproved privileged access",
                    "Identity monitoring",
                    0.95,
                    Instant.now()
                )
            );

            SecurityAlert second = new SecurityAlert(
                "ALT-4002",
                "Repeated failed authentication",
                "Multiple authentication failures",
                "SIEM",
                "authentication",
                "WS-102",
                Severity.MEDIUM,
                0.75,
                Instant.now()
            );

            SecurityAlert third = new SecurityAlert(
                "ALT-4003",
                "Authorized vulnerability scan",
                "Scheduled internal vulnerability scan",
                "EDR",
                "network",
                "SRV-003",
                Severity.HIGH,
                0.92,
                Instant.now()
            );

            third.addEvidence(
                new Evidence(
                    EvidenceType.AUTHORIZED_SCANNER,
                    "Approved security assessment",
                    "Change management",
                    0.98,
                    Instant.now()
                )
            );

            service.ingest(first);
            service.ingest(second);
            service.ingest(third);

            service.enrich(
                "ALT-4001",
                new Enrichment(
                    0.98,
                    0.95,
                    true,
                    true,
                    4,
                    "Infrastructure Security",
                    "Production identity server"
                )
            );

            service.enrich(
                "ALT-4002",
                new Enrichment(
                    0.45,
                    0.35,
                    false,
                    false,
                    2,
                    "End User Computing",
                    "Employee workstation"
                )
            );

            service.enrich(
                "ALT-4003",
                new Enrichment(
                    0.70,
                    0.05,
                    false,
                    false,
                    0,
                    "Security Engineering",
                    "Scanning infrastructure"
                )
            );

            service.triage("ALT-4001");
            service.triage("ALT-4002");
            service.triage("ALT-4003");

            List<SecurityAlert> processingOrder =
                new ArrayList<>(service.allAlerts());

            processingOrder.sort(
                Comparator.comparingDouble(
                    SecurityAlert::riskScore
                ).reversed()
            );

            for (SecurityAlert alert : processingOrder) {

                if (alert.verdict() == Verdict.FALSE_POSITIVE) {
                    System.out.println(
                        "Excluded from investigation: " + alert.id()
                    );
                    continue;
                }

                try {

                    Analyst analyst = service.assign(alert.id());

                    System.out.println(
                        "Assigned " + alert.id()
                        + " to " + analyst.id
                    );

                    service.investigate(
                        alert.id(),
                        analyst.id,
                        "Reviewed SIEM logs and endpoint telemetry.",
                        null
                    );

                    if (alert.id().equals("ALT-4001")) {

                        service.resolve(
                            alert.id(),
                            analyst.id,
                            Verdict.TRUE_POSITIVE,
                            "Unauthorized privileged access confirmed."
                        );

                        service.close(
                            alert.id(),
                            analyst.id
                        );

                    } else {

                        service.escalate(
                            alert.id(),
                            analyst.id,
                            "Additional forensic review required."
                        );
                    }

                } catch (CapacityException exception) {
                    System.err.println(exception.getMessage());
                }
            }

            new AlertReportService().print(
                service.allAlerts()
            );

            if (
                service.get("ALT-4001").status()
                != AlertStatus.CLOSED
            ) {
                throw new DomainException(
                    "Critical alert resolution assertion failed"
                );
            }

            if (
                service.get("ALT-4003").verdict()
                != Verdict.FALSE_POSITIVE
            ) {
                throw new DomainException(
                    "False-positive assertion failed"
                );
            }

            System.out.println(
                "\nAll enterprise workflow assertions passed."
            );

        } catch (RuntimeException exception) {

            System.err.println(
                "Enterprise workflow failure: "
                + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
