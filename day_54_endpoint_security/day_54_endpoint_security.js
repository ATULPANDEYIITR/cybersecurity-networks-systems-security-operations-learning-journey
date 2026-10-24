"use strict";

/*
 * Endpoint security policy and event-correlation engine.
 * Run with Node.js 18 or later: node endpoint-security.js
 *
 * This program processes synthetic telemetry. It does not inspect or
 * control the host operating system.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");

const Severity = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
});

const Sensor = Object.freeze({
  ANTIVIRUS: "antivirus",
  EDR: "edr",
  HIDS: "hids",
  BEHAVIORAL: "behavioral",
});

const IncidentState = Object.freeze({
  NEW: "new",
  TRIAGED: "triaged",
  CONTAINED: "contained",
  INVESTIGATING: "investigating",
  RESOLVED: "resolved",
});

const severityRank = new Map([
  [Severity.LOW, 1],
  [Severity.MEDIUM, 2],
  [Severity.HIGH, 3],
  [Severity.CRITICAL, 4],
]);

const transitions = new Map([
  [IncidentState.NEW, new Set([IncidentState.TRIAGED])],
  [
    IncidentState.TRIAGED,
    new Set([IncidentState.CONTAINED, IncidentState.INVESTIGATING]),
  ],
  [IncidentState.CONTAINED, new Set([IncidentState.INVESTIGATING])],
  [
    IncidentState.INVESTIGATING,
    new Set([IncidentState.CONTAINED, IncidentState.RESOLVED]),
  ],
  [IncidentState.RESOLVED, new Set()],
]);

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
  }
}

class TelemetryEvent {
  constructor({
    eventId,
    endpointId,
    timestamp,
    sensor,
    eventType,
    severity,
    processName,
    fileHash = null,
    userName = "unknown",
    details = {},
  }) {
    if (typeof eventId !== "string" || !eventId.trim()) {
      throw new ValidationError("eventId is required");
    }
    if (typeof endpointId !== "string" || !endpointId.trim()) {
      throw new ValidationError("endpointId is required");
    }

    const date = new Date(timestamp);
    if (!Number.isFinite(date.getTime())) {
      throw new ValidationError("Invalid timestamp");
    }
    if (!Object.values(Sensor).includes(sensor)) {
      throw new ValidationError("Unknown telemetry sensor");
    }
    if (!Object.values(Severity).includes(severity)) {
      throw new ValidationError("Unknown severity");
    }
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(processName)) {
      throw new ValidationError("Invalid process name");
    }
    if (fileHash !== null && !/^[a-fA-F0-9]{64}$/.test(fileHash)) {
      throw new ValidationError("File hash must be SHA-256 hexadecimal");
    }
    if (
      details === null ||
      typeof details !== "object" ||
      Array.isArray(details) ||
      Object.keys(details).length > 30
    ) {
      throw new ValidationError("Invalid telemetry details");
    }

    for (const [key, value] of Object.entries(details)) {
      if (
        typeof value !== "string" ||
        key.length > 100 ||
        value.length > 500
      ) {
        throw new ValidationError("Telemetry detail exceeds limits");
      }
    }

    this.eventId = eventId;
    this.endpointId = endpointId;
    this.timestamp = date.toISOString();
    this.sensor = sensor;
    this.eventType = eventType;
    this.severity = severity;
    this.processName = processName;
    this.fileHash = fileHash?.toLowerCase() ?? null;
    this.userName = userName;
    this.details = Object.freeze({ ...details });
    Object.freeze(this);
  }
}

class EndpointSecurityEngine {
  constructor({ trustedHashes = new Set(), clock = () => new Date() } = {}) {
    this.trustedHashes = new Set(
      [...trustedHashes].map((hash) => hash.toLowerCase()),
    );
    this.clock = clock;
    this.events = new Map();
    this.incidents = new Map();
    this.endpointStates = new Map();
    this.sequence = 0;
  }

  ingest(event) {
    if (!(event instanceof TelemetryEvent)) {
      throw new ValidationError("Expected a TelemetryEvent");
    }

    const existing = this.events.get(event.eventId);
    if (existing) {
      if (JSON.stringify(existing) !== JSON.stringify(event)) {
        throw new ValidationError("Conflicting duplicate event ID");
      }
      return false;
    }

    this.events.set(event.eventId, event);
    return true;
  }

  detect() {
    const grouped = new Map();

    for (const event of this.events.values()) {
      if (!grouped.has(event.endpointId)) {
        grouped.set(event.endpointId, []);
      }
      grouped.get(event.endpointId).push(event);
    }

    const created = [];

    for (const [endpointId, events] of grouped) {
      events.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));

      let severity = Severity.LOW;
      const evidence = new Set();
      const reasons = new Set();

      const record = (event, reason, level) => {
        evidence.add(event.eventId);
        reasons.add(reason);
        if (severityRank.get(level) > severityRank.get(severity)) {
          severity = level;
        }
      };

      for (const event of events) {
        if (
          event.sensor === Sensor.ANTIVIRUS &&
          event.eventType === "malware_detected"
        ) {
          record(event, "Antivirus malware detection", event.severity);
        }

        if (
          event.sensor === Sensor.ANTIVIRUS &&
          event.eventType === "quarantine_failed"
        ) {
          record(event, "Antivirus quarantine failed", Severity.HIGH);
        }

        if (
          event.sensor === Sensor.HIDS &&
          event.eventType === "integrity_violation"
        ) {
          record(event, "Protected-file integrity violation", event.severity);
        }
      }

      const suspicious = events.filter(
        (event) =>
          event.sensor === Sensor.EDR &&
          ["suspicious_process", "credential_access"].includes(event.eventType),
      );

      const outbound = events.filter(
        (event) =>
          event.sensor === Sensor.EDR &&
          event.eventType === "unusual_outbound_connection",
      );

      for (const event of suspicious) {
        record(event, `EDR event: ${event.eventType}`, event.severity);
      }

      if (suspicious.length > 0) {
        const firstTime = Math.min(
          ...suspicious.map((event) => Date.parse(event.timestamp)),
        );

        for (const event of outbound) {
          const elapsed = Date.parse(event.timestamp) - firstTime;
          if (elapsed >= 0 && elapsed <= 300_000) {
            record(
              event,
              "Suspicious execution correlated with outbound activity",
              Severity.CRITICAL,
            );
          }
        }
      }

      const failureCounts = new Map();
      for (const event of events) {
        if (event.sensor !== Sensor.BEHAVIORAL) continue;

        if (event.eventType === "authentication_failure") {
          failureCounts.set(
            event.userName,
            (failureCounts.get(event.userName) ?? 0) + 1,
          );
        } else if (
          event.eventType === "authentication_success" &&
          (failureCounts.get(event.userName) ?? 0) >= 5
        ) {
          record(
            event,
            `Repeated authentication failures followed by success for ${event.userName}`,
            Severity.HIGH,
          );
        }
      }

      if (evidence.size === 0) continue;

      const incidentId = `INC-${String(++this.sequence).padStart(5, "0")}`;
      const incident = {
        incidentId,
        endpointId,
        severity,
        eventIds: [...evidence],
        reasons: [...reasons],
        state: IncidentState.NEW,
        createdAt: this.clock().toISOString(),
      };

      this.incidents.set(incidentId, incident);
      created.push(incident);
    }

    return created;
  }

  transition(incidentId, nextState) {
    const incident = this.incidents.get(incidentId);
    if (!incident) throw new Error(`Unknown incident: ${incidentId}`);

    if (!Object.values(IncidentState).includes(nextState)) {
      throw new ValidationError("Unknown incident state");
    }

    if (!transitions.get(incident.state).has(nextState)) {
      throw new Error(
        `Invalid transition ${incident.state} -> ${nextState}`,
      );
    }

    incident.state = nextState;

    if (nextState === IncidentState.CONTAINED) {
      this.endpointStates.set(incident.endpointId, "isolated");
    } else if (nextState === IncidentState.RESOLVED) {
      this.endpointStates.set(incident.endpointId, "review_required");
    }

    return Object.freeze({ ...incident, eventIds: [...incident.eventIds] });
  }

  report() {
    const countBy = (items, field) => {
      const result = {};
      for (const item of items) {
        result[item[field]] = (result[item[field]] ?? 0) + 1;
      }
      return Object.fromEntries(Object.entries(result).sort());
    };

    return {
      generatedAt: this.clock().toISOString(),
      telemetryCount: this.events.size,
      incidentCount: this.incidents.size,
      bySeverity: countBy(this.incidents.values(), "severity"),
      byState: countBy(this.incidents.values(), "state"),
      endpointStates: Object.fromEntries(
        [...this.endpointStates.entries()].sort(),
      ),
    };
  }

  async exportReport(path) {
    const report = {
      report: this.report(),
      incidents: [...this.incidents.values()],
    };
    const temporaryPath = `${path}.${crypto.randomUUID()}.tmp`;

    try {
      await fs.writeFile(temporaryPath, JSON.stringify(report, null, 2), {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      await fs.rename(temporaryPath, path);
    } catch (error) {
      await fs.rm(temporaryPath, { force: true }).catch(() => {});
      throw error;
    }
  }
}

function makeEvent({
  eventId,
  endpointId,
  sensor,
  eventType,
  severity,
  processName,
  userName = "unknown",
  offsetMs = 0,
}) {
  return new TelemetryEvent({
    eventId,
    endpointId,
    timestamp: new Date(Date.UTC(2026, 9, 24, 4, 0, 0) + offsetMs),
    sensor,
    eventType,
    severity,
    processName,
    userName,
  });
}

function buildSampleEvents() {
  const events = [
    makeEvent({
      eventId: "EV-001",
      endpointId: "WS-101",
      sensor: Sensor.ANTIVIRUS,
      eventType: "malware_detected",
      severity: Severity.HIGH,
      processName: "invoice.exe",
    }),
    makeEvent({
      eventId: "EV-002",
      endpointId: "WS-202",
      sensor: Sensor.HIDS,
      eventType: "integrity_violation",
      severity: Severity.HIGH,
      processName: "sshd",
    }),
    makeEvent({
      eventId: "EV-003",
      endpointId: "WS-303",
      sensor: Sensor.EDR,
      eventType: "suspicious_process",
      severity: Severity.HIGH,
      processName: "powershell.exe",
      offsetMs: 1_000,
    }),
    makeEvent({
      eventId: "EV-004",
      endpointId: "WS-303",
      sensor: Sensor.EDR,
      eventType: "unusual_outbound_connection",
      severity: Severity.MEDIUM,
      processName: "powershell.exe",
      offsetMs: 30_000,
    }),
    ...Array.from({ length: 5 }, (_, index) =>
      makeEvent({
        eventId: `AUTH-${index + 1}`,
        endpointId: "WS-404",
        sensor: Sensor.BEHAVIORAL,
        eventType: "authentication_failure",
        severity: Severity.MEDIUM,
        processName: "login_service",
        userName: "svc-backup",
        offsetMs: index * 1_000,
      }),
    ),
    makeEvent({
      eventId: "AUTH-6",
      endpointId: "WS-404",
      sensor: Sensor.BEHAVIORAL,
      eventType: "authentication_success",
      severity: Severity.MEDIUM,
      processName: "login_service",
      userName: "svc-backup",
      offsetMs: 10_000,
    }),
  ];

  return events;
}

async function main() {
  const engine = new EndpointSecurityEngine();

  for (const event of buildSampleEvents()) {
    engine.ingest(event);
  }

  const incidents = engine.detect();

  for (const incident of incidents) {
    console.log(
      `${incident.incidentId} ${incident.endpointId} ` +
        `${incident.severity}: ${incident.reasons.join("; ")}`,
    );
  }

  const edrIncident = incidents.find((item) => item.endpointId === "WS-303");
  if (edrIncident) {
    engine.transition(edrIncident.incidentId, IncidentState.TRIAGED);
    engine.transition(edrIncident.incidentId, IncidentState.CONTAINED);
    engine.transition(edrIncident.incidentId, IncidentState.INVESTIGATING);
  }

  console.log(JSON.stringify(engine.report(), null, 2));

  if (process.argv.includes("--export")) {
    await engine.exportReport("./endpoint-security-report.json");
    console.log("Report exported to endpoint-security-report.json");
  }

  const original = buildSampleEvents()[0];
  engine.ingest(original);
  console.log("Identical duplicate ignored:", !engine.ingest(original));

  try {
    engine.transition("UNKNOWN", IncidentState.RESOLVED);
  } catch (error) {
    console.log("Expected validation:", error.message);
  }
}

main().catch((error) => {
  console.error("Endpoint security simulation failed:", error.message);
  process.exitCode = 1;
});
