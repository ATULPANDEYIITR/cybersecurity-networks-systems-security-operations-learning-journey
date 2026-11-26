"use strict";

/*
 * ALERT TRIAGE AND EVENT-DRIVEN INVESTIGATION SYSTEM
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library.
 *
 * Features:
 * - Event-driven alert processing.
 * - Confidence and severity evaluation.
 * - Contextual enrichment.
 * - False-positive classification.
 * - Risk-based prioritization.
 * - Analyst capacity management.
 * - Investigation workflow.
 * - Escalation and resolution.
 * - Immutable audit events.
 * - Operational metrics.
 */

const { EventEmitter } = require("node:events");
const crypto = require("node:crypto");

// ============================================================
// DOMAIN CONSTANTS
// ============================================================

const Severity = Object.freeze({
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    INFORMATIONAL: "informational"
});

const Status = Object.freeze({
    NEW: "new",
    ENRICHING: "enriching",
    TRIAGED: "triaged",
    ASSIGNED: "assigned",
    INVESTIGATING: "investigating",
    ESCALATED: "escalated",
    RESOLVED: "resolved",
    CLOSED: "closed"
});

const Verdict = Object.freeze({
    TRUE_POSITIVE: "true_positive",
    FALSE_POSITIVE: "false_positive",
    BENIGN_TRUE_POSITIVE: "benign_true_positive",
    UNDETERMINED: "undetermined"
});

const SeverityWeight = Object.freeze({
    critical: 1.00,
    high: 0.80,
    medium: 0.55,
    low: 0.30,
    informational: 0.10
});

const AllowedTransitions = Object.freeze({
    new: ["enriching", "closed"],
    enriching: ["triaged", "escalated"],
    triaged: ["assigned", "escalated", "closed"],
    assigned: ["investigating", "escalated"],
    investigating: ["escalated", "resolved"],
    escalated: ["investigating", "resolved"],
    resolved: ["closed"],
    closed: []
});

class ValidationError extends Error {}
class WorkflowError extends Error {}
class AuthorizationError extends Error {}
class CapacityError extends Error {}

// ============================================================
// VALIDATION
// ============================================================

function requireText(value, field) {
    if (typeof value !== "string" || value.trim() === "") {
        throw new ValidationError(`${field} must be non-empty text`);
    }
}

function requireProbability(value, field) {
    if (
        typeof value !== "number" ||
        !Number.isFinite(value) ||
        value < 0 ||
        value > 1
    ) {
        throw new ValidationError(
            `${field} must be between 0 and 1`
        );
    }
}

function requireEnum(value, allowed, field) {
    if (!allowed.includes(value)) {
        throw new ValidationError(`Invalid ${field}: ${value}`);
    }
}

// ============================================================
// IMMUTABLE AUDIT EVENT
// ============================================================

class AuditEvent {
    constructor(action, actor, details = {}) {
        this.eventId = crypto.randomUUID();
        this.timestamp = new Date().toISOString();
        this.action = action;
        this.actor = actor;

        // Prevent direct mutation of the recorded event.
        this.details = Object.freeze({ ...details });

        Object.freeze(this);
    }
}

// ============================================================
// ALERT MODEL
// ============================================================

class SecurityAlert {
    constructor({
        alertId,
        title,
        description,
        source,
        category,
        assetId,
        severity,
        confidence,
        observedAt = new Date()
    }) {
        requireText(alertId, "alertId");
        requireText(title, "title");
        requireText(source, "source");
        requireText(category, "category");
        requireText(assetId, "assetId");

        requireEnum(
            severity,
            Object.values(Severity),
            "severity"
        );

        requireProbability(confidence, "confidence");

        const timestamp = new Date(observedAt);

        if (Number.isNaN(timestamp.getTime())) {
            throw new ValidationError("Invalid observedAt timestamp");
        }

        this.alertId = alertId;
        this.title = title;
        this.description = description;
        this.source = source;
        this.category = category;
        this.assetId = assetId;
        this.severity = severity;
        this.confidence = confidence;
        this.observedAt = timestamp;

        this.status = Status.NEW;
        this.verdict = Verdict.UNDETERMINED;
        this.enrichment = null;
        this.riskScore = 0;

        this.evidence = [];
        this.notes = [];
        this.assignedAnalyst = null;
        this.auditEvents = [];
        this.version = 0;
    }

    record(action, actor, details = {}) {
        const event = new AuditEvent(
            action,
            actor,
            details
        );

        this.auditEvents.push(event);
        this.version++;

        return event;
    }
}

// ============================================================
// ENRICHMENT SERVICE
// ============================================================

class EnrichmentService {

    constructor(assetInventory, threatIntelligence) {
        this.assetInventory = assetInventory;
        this.threatIntelligence = threatIntelligence;
    }

    async enrich(alert) {
        const [asset, threat] = await Promise.all([
            Promise.resolve(
                this.assetInventory.get(alert.assetId)
            ),
            Promise.resolve(
                this.threatIntelligence.get(alert.category)
            )
        ]);

        if (!asset) {
            throw new WorkflowError(
                `Asset not found: ${alert.assetId}`
            );
        }

        const enrichment = {
            assetCriticality: asset.criticality,
            assetOwner: asset.owner,
            privilegedAsset: asset.privileged,
            threatScore: threat?.score ?? 0,
            knownMaliciousIndicator: threat?.confirmed ?? false,
            historicalAlertCount: asset.historicalAlerts ?? 0,
            businessContext: asset.businessContext
        };

        requireProbability(
            enrichment.assetCriticality,
            "assetCriticality"
        );

        requireProbability(
            enrichment.threatScore,
            "threatScore"
        );

        return Object.freeze(enrichment);
    }
}

// ============================================================
// RISK ENGINE
// ============================================================

class RiskEngine {

    static calculate(alert, enrichment) {
        const severity = SeverityWeight[alert.severity];

        const privilegedBonus =
            enrichment.privilegedAsset ? 0.10 : 0;

        const maliciousBonus =
            enrichment.knownMaliciousIndicator ? 0.15 : 0;

        const historicalBonus = Math.min(
            enrichment.historicalAlertCount * 0.01,
            0.10
        );

        const score =
            0.30 * severity +
            0.25 * alert.confidence +
            0.20 * enrichment.threatScore +
            0.25 * enrichment.assetCriticality +
            privilegedBonus +
            maliciousBonus +
            historicalBonus;

        return Math.min(1, Number(score.toFixed(4)));
    }

    static priority(score) {
        if (score >= 0.85) return "P1";
        if (score >= 0.70) return "P2";
        if (score >= 0.45) return "P3";
        return "P4";
    }
}

// ============================================================
// FALSE-POSITIVE EVALUATOR
// ============================================================

class VerdictEngine {

    static evaluate(alert, enrichment) {
        const confirmedMalicious = alert.evidence.some(
            item =>
                [
                    "malware_detection",
                    "confirmed_c2",
                    "unauthorized_access"
                ].includes(item.type) &&
                item.reliability >= 0.70
        );

        const verifiedBenign = alert.evidence.some(
            item =>
                [
                    "approved_activity",
                    "authorized_scanner",
                    "maintenance_window"
                ].includes(item.type) &&
                item.reliability >= 0.90
        );

        if (confirmedMalicious) {
            return Verdict.TRUE_POSITIVE;
        }

        if (verifiedBenign) {
            return Verdict.FALSE_POSITIVE;
        }

        if (
            alert.confidence >= 0.90 &&
            enrichment.knownMaliciousIndicator
        ) {
            return Verdict.TRUE_POSITIVE;
        }

        return Verdict.UNDETERMINED;
    }
}

// ============================================================
// ANALYST CAPACITY AND ASSIGNMENT
// ============================================================

class Analyst {
    constructor({
        id,
        name,
        tier,
        capacity,
        specialties = []
    }) {
        requireText(id, "analyst id");
        requireText(name, "analyst name");

        if (![1, 2, 3].includes(tier)) {
            throw new ValidationError("Tier must be 1, 2, or 3");
        }

        if (!Number.isInteger(capacity) || capacity < 1) {
            throw new ValidationError("Invalid capacity");
        }

        this.id = id;
        this.name = name;
        this.tier = tier;
        this.capacity = capacity;
        this.specialties = new Set(specialties);
        this.activeCases = new Set();
    }

    get available() {
        return this.activeCases.size < this.capacity;
    }
}

class AssignmentService {

    static requiredTier(alert) {
        if (alert.riskScore >= 0.85) return 3;
        if (alert.riskScore >= 0.65) return 2;
        return 1;
    }

    assign(alert, analysts) {
        if (alert.status !== Status.TRIAGED) {
            throw new WorkflowError(
                "Only triaged alerts can be assigned"
            );
        }

        if (alert.verdict === Verdict.FALSE_POSITIVE) {
            throw new WorkflowError(
                "False-positive alerts cannot be assigned for investigation"
            );
        }

        const requiredTier = AssignmentService.requiredTier(alert);

        const candidates = analysts
            .filter(
                analyst =>
                    analyst.available &&
                    analyst.tier >= requiredTier
            )
            .sort((a, b) => {
                const loadA = a.activeCases.size / a.capacity;
                const loadB = b.activeCases.size / b.capacity;

                return loadA - loadB || a.tier - b.tier;
            });

        if (candidates.length === 0) {
            throw new CapacityError(
                "No eligible analyst is available"
            );
        }

        const analyst = candidates[0];

        analyst.activeCases.add(alert.alertId);
        alert.assignedAnalyst = analyst.id;

        return analyst;
    }

    release(alert, analysts) {
        const analyst = analysts.find(
            item => item.id === alert.assignedAnalyst
        );

        if (analyst) {
            analyst.activeCases.delete(alert.alertId);
        }
    }
}

// ============================================================
// EVENT-DRIVEN TRIAGE CONTROLLER
// ============================================================

class AlertTriageController extends EventEmitter {

    constructor(enrichmentService, analysts) {
        super();

        this.enrichmentService = enrichmentService;
        this.analysts = analysts;
        this.assignmentService = new AssignmentService();

        this.alerts = new Map();
        this.processing = new Set();
    }

    transition(alert, nextStatus, actor) {
        if (
            !AllowedTransitions[alert.status].includes(nextStatus)
        ) {
            throw new WorkflowError(
                `Invalid transition ${alert.status} -> ${nextStatus}`
            );
        }

        const previous = alert.status;
        alert.status = nextStatus;

        alert.record(
            "status_transition",
            actor,
            {
                previous,
                current: nextStatus
            }
        );

        this.emit("statusChanged", {
            alertId: alert.alertId,
            previous,
            current: nextStatus
        });
    }

    async ingest(alert) {
        if (!(alert instanceof SecurityAlert)) {
            throw new ValidationError("Invalid alert object");
        }

        if (this.alerts.has(alert.alertId)) {
            throw new WorkflowError("Duplicate alert identifier");
        }

        this.alerts.set(alert.alertId, alert);

        alert.record("ingested", "ingestion_service");

        this.emit("alertReceived", {
            alertId: alert.alertId
        });

        return alert;
    }

    async process(alertId) {
        if (this.processing.has(alertId)) {
            throw new WorkflowError("Alert is already processing");
        }

        const alert = this.alerts.get(alertId);

        if (!alert) {
            throw new WorkflowError("Alert not found");
        }

        this.processing.add(alertId);

        try {
            this.transition(
                alert,
                Status.ENRICHING,
                "enrichment_service"
            );

            const enrichment =
                await this.enrichmentService.enrich(alert);

            alert.enrichment = enrichment;

            alert.record(
                "enriched",
                "enrichment_service",
                {
                    assetOwner: enrichment.assetOwner
                }
            );

            alert.riskScore = RiskEngine.calculate(
                alert,
                enrichment
            );

            alert.verdict = VerdictEngine.evaluate(
                alert,
                enrichment
            );

            this.transition(
                alert,
                Status.TRIAGED,
                "triage_engine"
            );

            const result = {
                alertId: alert.alertId,
                riskScore: alert.riskScore,
                priority: RiskEngine.priority(alert.riskScore),
                verdict: alert.verdict,
                status: alert.status
            };

            this.emit("triageCompleted", result);

            return result;

        } catch (error) {
            alert.record(
                "processing_failed",
                "triage_engine",
                { error: error.message }
            );

            this.emit("processingFailed", {
                alertId,
                message: error.message
            });

            throw error;

        } finally {
            this.processing.delete(alertId);
        }
    }

    assign(alertId) {
        const alert = this.alerts.get(alertId);

        if (!alert) {
            throw new WorkflowError("Alert not found");
        }

        const analyst = this.assignmentService.assign(
            alert,
            this.analysts
        );

        this.transition(
            alert,
            Status.ASSIGNED,
            "assignment_service"
        );

        alert.record(
            "analyst_assigned",
            "assignment_service",
            { analystId: analyst.id }
        );

        this.emit("alertAssigned", {
            alertId,
            analystId: analyst.id
        });

        return analyst;
    }

    investigate(alertId, analystId, finding, evidence = null) {
        const alert = this.alerts.get(alertId);

        if (!alert) {
            throw new WorkflowError("Alert not found");
        }

        if (alert.assignedAnalyst !== analystId) {
            throw new AuthorizationError(
                "Only the assigned analyst can investigate"
            );
        }

        if (
            ![Status.ASSIGNED, Status.INVESTIGATING].includes(
                alert.status
            )
        ) {
            throw new WorkflowError(
                "Alert is not available for investigation"
            );
        }

        requireText(finding, "finding");

        if (alert.status === Status.ASSIGNED) {
            this.transition(
                alert,
                Status.INVESTIGATING,
                analystId
            );
        }

        if (evidence) {
            requireProbability(
                evidence.reliability,
                "evidence reliability"
            );

            alert.evidence.push(
                Object.freeze({ ...evidence })
            );
        }

        alert.notes.push(finding);

        alert.verdict = VerdictEngine.evaluate(
            alert,
            alert.enrichment
        );

        alert.record(
            "investigation_update",
            analystId,
            { finding }
        );

        this.emit("investigationUpdated", {
            alertId,
            analystId
        });
    }

    escalate(alertId, actor, reason) {
        const alert = this.alerts.get(alertId);

        if (!alert) {
            throw new WorkflowError("Alert not found");
        }

        requireText(reason, "escalation reason");

        this.transition(
            alert,
            Status.ESCALATED,
            actor
        );

        alert.record(
            "escalated",
            actor,
            { reason }
        );

        this.emit("alertEscalated", {
            alertId,
            reason
        });
    }

    resolve(alertId, actor, verdict, findings) {
        const alert = this.alerts.get(alertId);

        if (!alert) {
            throw new WorkflowError("Alert not found");
        }

        if (
            ![Status.INVESTIGATING, Status.ESCALATED].includes(
                alert.status
            )
        ) {
            throw new WorkflowError(
                "Alert must be under investigation"
            );
        }

        requireEnum(
            verdict,
            Object.values(Verdict),
            "verdict"
        );

        if (verdict === Verdict.UNDETERMINED) {
            throw new WorkflowError(
                "Undetermined verdict cannot resolve an alert"
            );
        }

        requireText(findings, "resolution findings");

        alert.verdict = verdict;

        this.transition(
            alert,
            Status.RESOLVED,
            actor
        );

        alert.notes.push(findings);

        alert.record(
            "resolved",
            actor,
            { verdict, findings }
        );

        this.assignmentService.release(
            alert,
            this.analysts
        );

        this.emit("alertResolved", {
            alertId,
            verdict
        });
    }

    close(alertId, actor) {
        const alert = this.alerts.get(alertId);

        if (!alert) {
            throw new WorkflowError("Alert not found");
        }

        if (alert.status !== Status.RESOLVED) {
            throw new WorkflowError(
                "Only resolved alerts can be closed"
            );
        }

        this.transition(alert, Status.CLOSED, actor);

        alert.record("closed", actor);

        this.emit("alertClosed", {
            alertId
        });
    }
}

// ============================================================
// REPORTING
// ============================================================

class AlertAnalytics {

    static generate(alerts) {
        const report = {
            total: alerts.length,
            severity: new Map(),
            status: new Map(),
            verdict: new Map(),
            averageConfidence: 0,
            averageRisk: 0,
            falsePositiveRate: 0
        };

        for (const alert of alerts) {
            report.severity.set(
                alert.severity,
                (report.severity.get(alert.severity) || 0) + 1
            );

            report.status.set(
                alert.status,
                (report.status.get(alert.status) || 0) + 1
            );

            report.verdict.set(
                alert.verdict,
                (report.verdict.get(alert.verdict) || 0) + 1
            );

            report.averageConfidence += alert.confidence;
            report.averageRisk += alert.riskScore;
        }

        if (alerts.length > 0) {
            report.averageConfidence /= alerts.length;
            report.averageRisk /= alerts.length;

            report.falsePositiveRate =
                (report.verdict.get(Verdict.FALSE_POSITIVE) || 0)
                / alerts.length;
        }

        report.averageConfidence = Number(
            report.averageConfidence.toFixed(4)
        );

        report.averageRisk = Number(
            report.averageRisk.toFixed(4)
        );

        return report;
    }
}

// ============================================================
// EXECUTABLE SCENARIO
// ============================================================

async function main() {

    const inventory = new Map([
        [
            "SRV-001",
            {
                criticality: 0.98,
                owner: "Infrastructure Security",
                privileged: true,
                historicalAlerts: 4,
                businessContext: "Production identity server"
            }
        ],
        [
            "WS-102",
            {
                criticality: 0.45,
                owner: "End User Computing",
                privileged: false,
                historicalAlerts: 2,
                businessContext: "Employee workstation"
            }
        ],
        [
            "SRV-003",
            {
                criticality: 0.70,
                owner: "Security Engineering",
                privileged: false,
                historicalAlerts: 0,
                businessContext: "Scanning infrastructure"
            }
        ]
    ]);

    const intelligence = new Map([
        [
            "identity",
            {
                score: 0.95,
                confirmed: true
            }
        ],
        [
            "authentication",
            {
                score: 0.35,
                confirmed: false
            }
        ],
        [
            "network",
            {
                score: 0.05,
                confirmed: false
            }
        ]
    ]);

    const analysts = [
        new Analyst({
            id: "AN-01",
            name: "Analyst One",
            tier: 1,
            capacity: 4
        }),
        new Analyst({
            id: "AN-02",
            name: "Analyst Two",
            tier: 2,
            capacity: 5
        }),
        new Analyst({
            id: "AN-03",
            name: "Analyst Three",
            tier: 3,
            capacity: 5
        })
    ];

    const enrichmentService = new EnrichmentService(
        inventory,
        intelligence
    );

    const controller = new AlertTriageController(
        enrichmentService,
        analysts
    );

    controller.on("alertReceived", event => {
        console.log("RECEIVED:", event.alertId);
    });

    controller.on("triageCompleted", event => {
        console.log("TRIAGED:", event);
    });

    controller.on("alertEscalated", event => {
        console.log("ESCALATED:", event);
    });

    const alerts = [
        new SecurityAlert({
            alertId: "ALT-2001",
            title: "Suspicious privileged login",
            description: "Unusual administrator authentication",
            source: "SIEM",
            category: "identity",
            assetId: "SRV-001",
            severity: Severity.CRITICAL,
            confidence: 0.96
        }),
        new SecurityAlert({
            alertId: "ALT-2002",
            title: "Repeated failed authentication",
            description: "Multiple failed authentication attempts",
            source: "SIEM",
            category: "authentication",
            assetId: "WS-102",
            severity: Severity.MEDIUM,
            confidence: 0.75
        }),
        new SecurityAlert({
            alertId: "ALT-2003",
            title: "Scheduled vulnerability scan",
            description: "Internal authorized scanner activity",
            source: "EDR",
            category: "network",
            assetId: "SRV-003",
            severity: Severity.HIGH,
            confidence: 0.92
        })
    ];

    alerts[2].evidence.push({
        type: "authorized_scanner",
        description: "Approved maintenance window",
        reliability: 0.98
    });

    for (const alert of alerts) {
        await controller.ingest(alert);
    }

    for (const alert of alerts) {
        await controller.process(alert.alertId);
    }

    for (const alert of alerts) {
        if (alert.verdict === Verdict.FALSE_POSITIVE) {
            console.log(
                "SUPPRESSED FROM INVESTIGATION:",
                alert.alertId
            );
            continue;
        }

        try {
            const analyst = controller.assign(alert.alertId);

            controller.investigate(
                alert.alertId,
                analyst.id,
                "Reviewed endpoint telemetry and authentication logs."
            );

            if (alert.alertId === "ALT-2001") {
                controller.resolve(
                    alert.alertId,
                    analyst.id,
                    Verdict.TRUE_POSITIVE,
                    "Unauthorized privileged access confirmed."
                );

                controller.close(
                    alert.alertId,
                    analyst.id
                );
            } else {
                controller.escalate(
                    alert.alertId,
                    analyst.id,
                    "Additional forensic investigation required."
                );
            }

        } catch (error) {
            console.error(
                "Workflow failure:",
                alert.alertId,
                error.message
            );
        }
    }

    const report = AlertAnalytics.generate(alerts);

    console.log("\nFINAL REPORT");

    console.log(
        JSON.stringify(
            {
                total: report.total,
                severity: Object.fromEntries(report.severity),
                status: Object.fromEntries(report.status),
                verdict: Object.fromEntries(report.verdict),
                averageConfidence: report.averageConfidence,
                averageRisk: report.averageRisk,
                falsePositiveRate: report.falsePositiveRate
            },
            null,
            2
        )
    );

    console.log("\nAUDIT EVENT COUNTS");

    for (const alert of alerts) {
        console.log(
            alert.alertId,
            alert.status,
            alert.auditEvents.length
        );
    }

    // Runtime assertions.
    if (alerts.length !== 3) {
        throw new Error("Alert ingestion assertion failed");
    }

    if (alerts[2].verdict !== Verdict.FALSE_POSITIVE) {
        throw new Error("False-positive assertion failed");
    }

    if (alerts[0].status !== Status.CLOSED) {
        throw new Error("Resolution assertion failed");
    }

    console.log("\nAll runtime assertions passed.");
}

main().catch(error => {
    console.error("Fatal execution error:", error);
    process.exitCode = 1;
});
