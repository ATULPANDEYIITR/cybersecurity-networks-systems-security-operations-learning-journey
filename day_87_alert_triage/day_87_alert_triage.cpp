#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <queue>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/*
 * ALERT TRIAGE AND REPOSITORY-STYLE GOVERNANCE ENGINE
 *
 * Standard: C++17
 * Dependencies: Standard C++ library.
 *
 * Implements:
 * - Alert domain modeling.
 * - Severity and confidence evaluation.
 * - Threat and asset enrichment.
 * - Evidence-based false-positive classification.
 * - Risk calculation.
 * - Priority queue processing.
 * - Analyst authorization and capacity.
 * - Investigation state transitions.
 * - Escalation and resolution.
 * - Operational reporting.
 */

namespace triage {

// ============================================================
// DOMAIN ENUMERATIONS
// ============================================================

enum class Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational
};

enum class Status {
    New,
    Enriching,
    Triaged,
    Assigned,
    Investigating,
    Escalated,
    Resolved,
    Closed
};

enum class Verdict {
    TruePositive,
    FalsePositive,
    BenignTruePositive,
    Undetermined
};

enum class EvidenceType {
    MalwareDetection,
    ConfirmedC2,
    UnauthorizedAccess,
    ApprovedActivity,
    AuthorizedScanner,
    MaintenanceWindow,
    Other
};

enum class AnalystTier {
    L1 = 1,
    L2 = 2,
    L3 = 3
};

// ============================================================
// STRING CONVERSION
// ============================================================

std::string toString(Severity value) {
    switch (value) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
        case Severity::Informational: return "INFORMATIONAL";
    }
    throw std::logic_error("Unknown severity");
}

std::string toString(Status value) {
    switch (value) {
        case Status::New: return "NEW";
        case Status::Enriching: return "ENRICHING";
        case Status::Triaged: return "TRIAGED";
        case Status::Assigned: return "ASSIGNED";
        case Status::Investigating: return "INVESTIGATING";
        case Status::Escalated: return "ESCALATED";
        case Status::Resolved: return "RESOLVED";
        case Status::Closed: return "CLOSED";
    }
    throw std::logic_error("Unknown status");
}

std::string toString(Verdict value) {
    switch (value) {
        case Verdict::TruePositive: return "TRUE_POSITIVE";
        case Verdict::FalsePositive: return "FALSE_POSITIVE";
        case Verdict::BenignTruePositive:
            return "BENIGN_TRUE_POSITIVE";
        case Verdict::Undetermined: return "UNDETERMINED";
    }
    throw std::logic_error("Unknown verdict");
}

// ============================================================
// VALIDATION
// ============================================================

void validateProbability(
    double value,
    const std::string& field
) {
    if (!std::isfinite(value) || value < 0.0 || value > 1.0) {
        throw std::invalid_argument(
            field + " must be between 0 and 1"
        );
    }
}

void validateText(
    const std::string& value,
    const std::string& field
) {
    if (value.empty()) {
        throw std::invalid_argument(
            field + " cannot be empty"
        );
    }
}

// ============================================================
// DOMAIN STRUCTURES
// ============================================================

struct Evidence {
    EvidenceType type;
    std::string description;
    std::string source;
    double reliability;

    Evidence(
        EvidenceType type,
        std::string description,
        std::string source,
        double reliability
    )
        : type(type),
          description(std::move(description)),
          source(std::move(source)),
          reliability(reliability) {

        validateText(this->description, "Evidence description");
        validateText(this->source, "Evidence source");

        validateProbability(
            reliability,
            "Evidence reliability"
        );
    }
};

struct Enrichment {
    double assetCriticality = 0.5;
    double threatScore = 0.0;
    bool maliciousIndicator = false;
    bool privilegedAsset = false;
    int historicalAlerts = 0;
    std::string owner;
    std::string businessContext;

    void validate() const {
        validateProbability(
            assetCriticality,
            "Asset criticality"
        );

        validateProbability(
            threatScore,
            "Threat score"
        );

        if (historicalAlerts < 0) {
            throw std::invalid_argument(
                "Historical alerts cannot be negative"
            );
        }

        validateText(owner, "Asset owner");
    }
};

struct AuditEvent {
    std::string action;
    std::string actor;
    std::string details;
};

struct Alert {
    std::string id;
    std::string title;
    std::string assetId;
    std::string source;
    std::string category;

    Severity severity;
    double confidence;

    Status status = Status::New;
    Verdict verdict = Verdict::Undetermined;

    Enrichment enrichment;

    double riskScore = 0.0;

    std::optional<std::string> assignedAnalyst;

    std::vector<Evidence> evidence;
    std::vector<std::string> findings;
    std::vector<AuditEvent> audit;

    Alert(
        std::string id,
        std::string title,
        std::string assetId,
        std::string source,
        std::string category,
        Severity severity,
        double confidence
    )
        : id(std::move(id)),
          title(std::move(title)),
          assetId(std::move(assetId)),
          source(std::move(source)),
          category(std::move(category)),
          severity(severity),
          confidence(confidence) {

        validateText(this->id, "Alert ID");
        validateText(this->title, "Alert title");
        validateText(this->assetId, "Asset ID");
        validateText(this->source, "Source");
        validateProbability(confidence, "Confidence");
    }

    void record(
        const std::string& action,
        const std::string& actor,
        const std::string& details = ""
    ) {
        audit.push_back({
            action,
            actor,
            details
        });
    }
};

struct Analyst {
    std::string id;
    std::string name;
    AnalystTier tier;
    std::size_t capacity;
    std::set<std::string> specialties;
    std::set<std::string> activeAlerts;

    bool available() const {
        return activeAlerts.size() < capacity;
    }
};

// ============================================================
// RISK SCORING
// ============================================================

class RiskEngine {

public:

    static double severityWeight(Severity severity) {
        switch (severity) {
            case Severity::Critical: return 1.00;
            case Severity::High: return 0.80;
            case Severity::Medium: return 0.55;
            case Severity::Low: return 0.30;
            case Severity::Informational: return 0.10;
        }

        throw std::logic_error("Invalid severity");
    }

    static double calculate(Alert& alert) {

        alert.enrichment.validate();

        const auto& context = alert.enrichment;

        double score =
            0.30 * severityWeight(alert.severity)
            + 0.25 * alert.confidence
            + 0.20 * context.threatScore
            + 0.25 * context.assetCriticality;

        if (context.privilegedAsset) {
            score += 0.10;
        }

        if (context.maliciousIndicator) {
            score += 0.15;
        }

        score += std::min(
            context.historicalAlerts * 0.01,
            0.10
        );

        alert.riskScore = std::min(score, 1.0);

        return alert.riskScore;
    }

    static int requiredTier(double risk) {
        if (risk >= 0.85) return 3;
        if (risk >= 0.65) return 2;
        return 1;
    }

    static std::string priority(double risk) {
        if (risk >= 0.85) return "P1";
        if (risk >= 0.70) return "P2";
        if (risk >= 0.45) return "P3";
        return "P4";
    }
};

// ============================================================
// EVIDENCE EVALUATION
// ============================================================

class VerdictEngine {

public:

    static Verdict evaluate(const Alert& alert) {

        for (const auto& item : alert.evidence) {

            if (
                (
                    item.type == EvidenceType::MalwareDetection
                    || item.type == EvidenceType::ConfirmedC2
                    || item.type == EvidenceType::UnauthorizedAccess
                )
                && item.reliability >= 0.70
            ) {
                return Verdict::TruePositive;
            }
        }

        for (const auto& item : alert.evidence) {

            if (
                (
                    item.type == EvidenceType::ApprovedActivity
                    || item.type == EvidenceType::AuthorizedScanner
                    || item.type == EvidenceType::MaintenanceWindow
                )
                && item.reliability >= 0.90
            ) {
                return Verdict::FalsePositive;
            }
        }

        if (
            alert.confidence >= 0.90
            && alert.enrichment.maliciousIndicator
        ) {
            return Verdict::TruePositive;
        }

        return Verdict::Undetermined;
    }
};

// ============================================================
// PRIORITY QUEUE
// ============================================================

struct QueueItem {
    double risk;
    std::string alertId;
};

struct PriorityComparator {
    bool operator()(
        const QueueItem& left,
        const QueueItem& right
    ) const {
        if (left.risk != right.risk) {
            return left.risk < right.risk;
        }

        return left.alertId > right.alertId;
    }
};

// ============================================================
// GOVERNANCE AND WORKFLOW ENGINE
// ============================================================

class TriageEngine {

private:

    std::unordered_map<std::string, Alert> alerts;

    std::unordered_map<std::string, Analyst> analysts;

    std::priority_queue<
        QueueItem,
        std::vector<QueueItem>,
        PriorityComparator
    > queue;

    bool validTransition(
        Status current,
        Status next
    ) const {

        switch (current) {
            case Status::New:
                return next == Status::Enriching
                    || next == Status::Closed;

            case Status::Enriching:
                return next == Status::Triaged
                    || next == Status::Escalated;

            case Status::Triaged:
                return next == Status::Assigned
                    || next == Status::Escalated
                    || next == Status::Closed;

            case Status::Assigned:
                return next == Status::Investigating
                    || next == Status::Escalated;

            case Status::Investigating:
                return next == Status::Escalated
                    || next == Status::Resolved;

            case Status::Escalated:
                return next == Status::Investigating
                    || next == Status::Resolved;

            case Status::Resolved:
                return next == Status::Closed;

            case Status::Closed:
                return false;
        }

        return false;
    }

    void transition(
        Alert& alert,
        Status next,
        const std::string& actor
    ) {
        if (!validTransition(alert.status, next)) {
            throw std::logic_error(
                "Invalid alert state transition"
            );
        }

        Status previous = alert.status;

        alert.status = next;

        alert.record(
            "status_transition",
            actor,
            toString(previous) + " -> " + toString(next)
        );
    }

public:

    void addAnalyst(Analyst analyst) {
        validateText(analyst.id, "Analyst ID");
        validateText(analyst.name, "Analyst name");

        if (analyst.capacity == 0) {
            throw std::invalid_argument(
                "Analyst capacity must be positive"
            );
        }

        if (analysts.count(analyst.id)) {
            throw std::invalid_argument(
                "Duplicate analyst ID"
            );
        }

        analysts.emplace(
            analyst.id,
            std::move(analyst)
        );
    }

    void ingest(Alert alert) {

        if (alerts.count(alert.id)) {
            throw std::invalid_argument(
                "Duplicate alert ID"
            );
        }

        alert.record(
            "alert_ingested",
            "ingestion_service"
        );

        alerts.emplace(
            alert.id,
            std::move(alert)
        );
    }

    Alert& getAlert(const std::string& id) {

        auto it = alerts.find(id);

        if (it == alerts.end()) {
            throw std::out_of_range("Alert not found");
        }

        return it->second;
    }

    void enrich(
        const std::string& id,
        const Enrichment& enrichment
    ) {
        Alert& alert = getAlert(id);

        transition(
            alert,
            Status::Enriching,
            "enrichment_service"
        );

        enrichment.validate();

        alert.enrichment = enrichment;

        alert.record(
            "enriched",
            "enrichment_service"
        );
    }

    void triage(const std::string& id) {

        Alert& alert = getAlert(id);

        if (alert.status != Status::Enriching) {
            throw std::logic_error(
                "Enrichment required before triage"
            );
        }

        alert.riskScore = RiskEngine::calculate(alert);

        alert.verdict = VerdictEngine::evaluate(alert);

        transition(
            alert,
            Status::Triaged,
            "triage_engine"
        );

        alert.record(
            "triage_completed",
            "triage_engine",
            "Risk=" + std::to_string(alert.riskScore)
        );

        if (alert.verdict != Verdict::FalsePositive) {
            queue.push({
                alert.riskScore,
                alert.id
            });
        }
    }

    std::optional<std::string> assign(
        const std::string& alertId
    ) {

        Alert& alert = getAlert(alertId);

        if (alert.status != Status::Triaged) {
            throw std::logic_error(
                "Only triaged alerts can be assigned"
            );
        }

        if (alert.verdict == Verdict::FalsePositive) {
            throw std::logic_error(
                "False positives cannot be assigned"
            );
        }

        int required = RiskEngine::requiredTier(
            alert.riskScore
        );

        Analyst* selected = nullptr;

        double lowestLoad = 2.0;

        for (auto& entry : analysts) {

            Analyst& analyst = entry.second;

            int tier = static_cast<int>(analyst.tier);

            if (
                tier < required
                || !analyst.available()
            ) {
                continue;
            }

            double load =
                static_cast<double>(
                    analyst.activeAlerts.size()
                ) / analyst.capacity;

            if (
                selected == nullptr
                || load < lowestLoad
                || (
                    load == lowestLoad
                    && tier < static_cast<int>(selected->tier)
                )
            ) {
                selected = &analyst;
                lowestLoad = load;
            }
        }

        if (selected == nullptr) {
            return std::nullopt;
        }

        selected->activeAlerts.insert(alert.id);

        alert.assignedAnalyst = selected->id;

        transition(
            alert,
            Status::Assigned,
            "assignment_service"
        );

        alert.record(
            "analyst_assigned",
            "assignment_service",
            selected->id
        );

        return selected->id;
    }

    void investigate(
        const std::string& alertId,
        const std::string& analystId,
        const std::string& finding,
        std::optional<Evidence> evidence = std::nullopt
    ) {

        Alert& alert = getAlert(alertId);

        if (
            !alert.assignedAnalyst
            || *alert.assignedAnalyst != analystId
        ) {
            throw std::runtime_error(
                "Analyst authorization failed"
            );
        }

        if (
            alert.status != Status::Assigned
            && alert.status != Status::Investigating
        ) {
            throw std::logic_error(
                "Alert is not investigable"
            );
        }

        validateText(finding, "Investigation finding");

        if (alert.status == Status::Assigned) {
            transition(
                alert,
                Status::Investigating,
                analystId
            );
        }

        if (evidence.has_value()) {
            alert.evidence.push_back(*evidence);
        }

        alert.findings.push_back(finding);

        alert.verdict = VerdictEngine::evaluate(alert);

        alert.record(
            "investigation_update",
            analystId
        );
    }

    void escalate(
        const std::string& alertId,
        const std::string& actor,
        const std::string& reason
    ) {

        Alert& alert = getAlert(alertId);

        validateText(reason, "Escalation reason");

        transition(
            alert,
            Status::Escalated,
            actor
        );

        alert.record(
            "escalated",
            actor,
            reason
        );
    }

    void resolve(
        const std::string& alertId,
        const std::string& actor,
        Verdict verdict,
        const std::string& findings
    ) {

        Alert& alert = getAlert(alertId);

        if (
            alert.status != Status::Investigating
            && alert.status != Status::Escalated
        ) {
            throw std::logic_error(
                "Alert must be investigated before resolution"
            );
        }

        if (verdict == Verdict::Undetermined) {
            throw std::invalid_argument(
                "Cannot resolve an undetermined alert"
            );
        }

        validateText(findings, "Resolution findings");

        alert.verdict = verdict;

        transition(
            alert,
            Status::Resolved,
            actor
        );

        alert.findings.push_back(findings);

        alert.record(
            "resolved",
            actor,
            toString(verdict)
        );

        if (alert.assignedAnalyst) {

            auto it = analysts.find(
                *alert.assignedAnalyst
            );

            if (it != analysts.end()) {
                it->second.activeAlerts.erase(alert.id);
            }
        }
    }

    void close(
        const std::string& alertId,
        const std::string& actor
    ) {

        Alert& alert = getAlert(alertId);

        transition(
            alert,
            Status::Closed,
            actor
        );

        alert.record("closed", actor);
    }

    void processQueue() {

        while (!queue.empty()) {

            QueueItem item = queue.top();
            queue.pop();

            Alert& alert = getAlert(item.alertId);

            if (alert.status != Status::Triaged) {
                continue;
            }

            std::cout
                << "QUEUE "
                << alert.id
                << " RISK "
                << std::fixed
                << std::setprecision(3)
                << alert.riskScore
                << " PRIORITY "
                << RiskEngine::priority(alert.riskScore)
                << '\n';

            auto assigned = assign(alert.id);

            if (!assigned.has_value()) {
                std::cout
                    << "NO ANALYST AVAILABLE: "
                    << alert.id
                    << '\n';

                continue;
            }

            std::cout
                << "ASSIGNED TO "
                << *assigned
                << '\n';

            investigate(
                alert.id,
                *assigned,
                "Reviewed SIEM records and endpoint telemetry."
            );

            if (alert.id == "ALT-3001") {

                resolve(
                    alert.id,
                    *assigned,
                    Verdict::TruePositive,
                    "Unauthorized privileged access confirmed."
                );

                close(alert.id, *assigned);

            } else {

                escalate(
                    alert.id,
                    *assigned,
                    "Additional forensic review required."
                );
            }
        }
    }

    void report() const {

        std::map<std::string, int> statusCounts;
        std::map<std::string, int> verdictCounts;
        std::map<std::string, int> severityCounts;

        double totalConfidence = 0.0;
        double totalRisk = 0.0;
        int falsePositives = 0;

        for (const auto& entry : alerts) {

            const Alert& alert = entry.second;

            statusCounts[toString(alert.status)]++;
            verdictCounts[toString(alert.verdict)]++;
            severityCounts[toString(alert.severity)]++;

            totalConfidence += alert.confidence;
            totalRisk += alert.riskScore;

            if (alert.verdict == Verdict::FalsePositive) {
                falsePositives++;
            }
        }

        const std::size_t total = alerts.size();

        std::cout << "\nSECURITY OPERATIONS REPORT\n";

        std::cout << "Total alerts: " << total << '\n';

        if (total == 0) {
            return;
        }

        std::cout
            << "Average confidence: "
            << totalConfidence / total
            << '\n';

        std::cout
            << "Average risk: "
            << totalRisk / total
            << '\n';

        std::cout
            << "False-positive rate: "
            << static_cast<double>(falsePositives) / total
            << '\n';

        std::cout << "\nSTATUS DISTRIBUTION\n";

        for (const auto& entry : statusCounts) {
            std::cout
                << entry.first
                << ": "
                << entry.second
                << '\n';
        }

        std::cout << "\nVERDICT DISTRIBUTION\n";

        for (const auto& entry : verdictCounts) {
            std::cout
                << entry.first
                << ": "
                << entry.second
                << '\n';
        }

        std::cout << "\nSEVERITY DISTRIBUTION\n";

        for (const auto& entry : severityCounts) {
            std::cout
                << entry.first
                << ": "
                << entry.second
                << '\n';
        }

        std::cout << "\nALERT AUDIT COUNTS\n";

        for (const auto& entry : alerts) {
            const Alert& alert = entry.second;

            std::cout
                << alert.id
                << " | "
                << toString(alert.status)
                << " | "
                << alert.audit.size()
                << '\n';
        }
    }
};

// ============================================================
// EXECUTABLE SCENARIO
// ============================================================

int main() {

    try {

        TriageEngine engine;

        engine.addAnalyst({
            "AN-01",
            "Analyst One",
            AnalystTier::L1,
            4,
            {"authentication"},
            {}
        });

        engine.addAnalyst({
            "AN-02",
            "Analyst Two",
            AnalystTier::L2,
            5,
            {"network", "endpoint"},
            {}
        });

        engine.addAnalyst({
            "AN-03",
            "Analyst Three",
            AnalystTier::L3,
            5,
            {"identity", "forensics"},
            {}
        });

        Alert first(
            "ALT-3001",
            "Suspicious privileged login",
            "SRV-001",
            "SIEM",
            "identity",
            Severity::Critical,
            0.96
        );

        first.evidence.emplace_back(
            EvidenceType::UnauthorizedAccess,
            "Unauthorized privileged access",
            "Identity monitoring",
            0.95
        );

        Alert second(
            "ALT-3002",
            "Repeated authentication failures",
            "WS-102",
            "SIEM",
            "authentication",
            Severity::Medium,
            0.75
        );

        Alert third(
            "ALT-3003",
            "Scheduled vulnerability scan",
            "SRV-003",
            "EDR",
            "network",
            Severity::High,
            0.92
        );

        third.evidence.emplace_back(
            EvidenceType::AuthorizedScanner,
            "Approved vulnerability scan",
            "Change management",
            0.98
        );

        engine.ingest(std::move(first));
        engine.ingest(std::move(second));
        engine.ingest(std::move(third));

        engine.enrich(
            "ALT-3001",
            {
                0.98,
                0.95,
                true,
                true,
                4,
                "Infrastructure Security",
                "Production identity server"
            }
        );

        engine.enrich(
            "ALT-3002",
            {
                0.45,
                0.35,
                false,
                false,
                2,
                "End User Computing",
                "Employee workstation"
            }
        );

        engine.enrich(
            "ALT-3003",
            {
                0.70,
                0.05,
                false,
                false,
                0,
                "Security Engineering",
                "Scanning infrastructure"
            }
        );

        engine.triage("ALT-3001");
        engine.triage("ALT-3002");
        engine.triage("ALT-3003");

        engine.processQueue();

        engine.report();

        // Validate important domain invariants.
        if (
            engine.getAlert("ALT-3001").status
            != Status::Closed
        ) {
            throw std::runtime_error(
                "Critical alert resolution assertion failed"
            );
        }

        if (
            engine.getAlert("ALT-3003").verdict
            != Verdict::FalsePositive
        ) {
            throw std::runtime_error(
                "False-positive classification assertion failed"
            );
        }

        std::cout
            << "\nAll validation assertions passed.\n";

    } catch (const std::exception& exception) {

        std::cerr
            << "Execution error: "
            << exception.what()
            << '\n';

        return 1;
    }

    return 0;
}
