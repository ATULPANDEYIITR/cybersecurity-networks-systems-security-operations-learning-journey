"use strict";

/*
 * Linux Security Monitoring event processor.
 * Run: node linux-security-monitor.js
 *
 * Processes synthetic telemetry by default. It does not attempt to collect
 * privileged host data, block addresses, terminate processes, or change files.
 */

const SEVERITY = Object.freeze({
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
});

class SecurityEvent {
  constructor({ timestamp, category, source, type, details = {} }) {
    if (!timestamp || !category || !source || !type) {
      throw new TypeError("timestamp, category, source, and type are required");
    }
    if (Number.isNaN(Date.parse(timestamp))) {
      throw new TypeError(`Invalid event timestamp: ${timestamp}`);
    }

    this.timestamp = timestamp;
    this.category = category;
    this.source = source;
    this.type = type;
    this.details = Object.freeze({ ...details });
    Object.freeze(this);
  }
}

class Alert {
  constructor({ severity, title, evidence, recommendation }) {
    if (!(severity in SEVERITY)) {
      throw new TypeError(`Unknown severity: ${severity}`);
    }

    this.severity = severity;
    this.title = title;
    this.evidence = Object.freeze({ ...evidence });
    this.recommendation = recommendation;
    Object.freeze(this);
  }
}

function parseEndpoint(endpoint) {
  if (typeof endpoint !== "string" || endpoint.length === 0) {
    throw new TypeError("Endpoint must be a non-empty string");
  }

  // Bracketed IPv6 endpoints must be split after the closing bracket.
  const ipv6 = endpoint.match(/^\[([^\]]+)\]:(\d+)$/);
  if (ipv6) {
    const port = Number(ipv6[2]);
    if (port < 0 || port > 65535) throw new RangeError("Invalid port");
    return { address: ipv6[1], port };
  }

  const ipv4OrWildcard = endpoint.match(/^([^:]+):(\d+)$/);
  if (ipv4OrWildcard) {
    const port = Number(ipv4OrWildcard[2]);
    if (port < 0 || port > 65535) throw new RangeError("Invalid port");
    return { address: ipv4OrWildcard[1], port };
  }

  throw new TypeError(`Unsupported endpoint format: ${endpoint}`);
}

function analyzeListener(connection) {
  if (!connection || typeof connection !== "object") {
    throw new TypeError("Connection must be an object");
  }
  if (String(connection.state).toUpperCase() !== "LISTEN") return null;

  const endpoint = parseEndpoint(connection.local);
  const wildcard = ["0.0.0.0", "::", "*"].includes(endpoint.address);
  let severity = "INFO";
  let title = "Review listener ownership and purpose";

  if ([2375].includes(endpoint.port)) {
    severity = "HIGH";
    title = "Docker API may be exposed without transport security";
  } else if ([3306, 5432, 6379, 27017].includes(endpoint.port)) {
    severity = "MEDIUM";
    title = "Database or cache listener requires exposure review";
  } else if ([4444, 5555, 31337].includes(endpoint.port)) {
    severity = "MEDIUM";
    title = "Unusual listening port requires process attribution";
  } else if (endpoint.port === 22) {
    severity = "LOW";
    title = "SSH listener requires access-policy validation";
  }

  if (wildcard && SEVERITY.MEDIUM > SEVERITY[severity]) {
    severity = "MEDIUM";
    title = "Wildcard-bound listener requires exposure review";
  }

  return new Alert({
    severity,
    title,
    evidence: {
      local: connection.local,
      protocol: connection.protocol ?? "unknown",
      pid: connection.pid ?? null,
      process: connection.process ?? "unknown",
      wildcard,
    },
    recommendation:
      "Confirm the owning process, intended network exposure, firewall policy, and service authentication.",
  });
}

function analyzeAuthentication(events, threshold = 5) {
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new RangeError("threshold must be a positive integer");
  }

  const failuresBySource = new Map();
  const failuresByAccount = new Map();
  const alerts = [];

  for (const event of events) {
    if (!(event instanceof SecurityEvent)) {
      throw new TypeError("Authentication input must contain SecurityEvent objects");
    }
    if (event.category !== "authentication") continue;

    const outcome = String(event.details.outcome ?? "").toLowerCase();
    const source = String(event.details.sourceIp ?? "unknown");
    const account = String(event.details.username ?? "unknown");

    if (["failed", "failure", "invalid"].includes(outcome)) {
      failuresBySource.set(source, (failuresBySource.get(source) ?? 0) + 1);
      failuresByAccount.set(account, (failuresByAccount.get(account) ?? 0) + 1);
    }

    if (outcome === "success" && Number(event.details.precedingFailures ?? 0) >= threshold) {
      alerts.push(new Alert({
        severity: "HIGH",
        title: "Authentication succeeded after repeated failures",
        evidence: {
          sourceIp: source,
          username: account,
          precedingFailures: Number(event.details.precedingFailures),
          timestamp: event.timestamp,
        },
        recommendation:
          "Validate the session, MFA outcome, source reputation, and account-owner confirmation.",
      }));
    }
  }

  for (const [sourceIp, count] of failuresBySource) {
    if (count >= threshold) {
      alerts.push(new Alert({
        severity: count >= threshold * 2 ? "HIGH" : "MEDIUM",
        title: "Repeated authentication failures from a source",
        evidence: { sourceIp, failureCount: count },
        recommendation:
          "Correlate authentication failures with identity logs and network telemetry before blocking traffic.",
      }));
    }
  }

  for (const [username, count] of failuresByAccount) {
    if (count >= threshold) {
      alerts.push(new Alert({
        severity: "MEDIUM",
        title: "Repeated authentication failures against an account",
        evidence: { username, failureCount: count },
        recommendation:
          "Distinguish password spraying, stale service credentials, and legitimate user mistakes.",
      }));
    }
  }

  return alerts;
}

class EventProcessor {
  #seen = new Set();
  #alerts = [];

  ingest(event) {
    if (!(event instanceof SecurityEvent)) {
      throw new TypeError("Only validated SecurityEvent instances are accepted");
    }

    // Deduplication prevents a retried ingestion request from inflating counts.
    const identity = [
      event.timestamp,
      event.category,
      event.source,
      event.type,
      JSON.stringify(event.details),
    ].join("|");

    if (this.#seen.has(identity)) return false;
    this.#seen.add(identity);

    if (event.category === "network" && event.type === "listener") {
      const alert = analyzeListener(event.details);
      if (alert) this.#alerts.push(alert);
    }

    return true;
  }

  addAlerts(alerts) {
    for (const alert of alerts) {
      if (!(alert instanceof Alert)) throw new TypeError("Invalid alert object");
      this.#alerts.push(alert);
    }
  }

  getAlerts() {
    return [...this.#alerts].sort(
      (a, b) => SEVERITY[b.severity] - SEVERITY[a.severity],
    );
  }

  summary() {
    const counts = Object.fromEntries(
      Object.keys(SEVERITY).map((severity) => [severity, 0]),
    );

    for (const alert of this.#alerts) counts[alert.severity] += 1;

    return {
      uniqueEvents: this.#seen.size,
      totalAlerts: this.#alerts.length,
      severityCounts: counts,
    };
  }
}

function buildDemoEvents() {
  const base = Date.parse("2026-10-10T06:00:00.000Z");
  const events = [];

  for (let index = 0; index < 6; index += 1) {
    events.push(new SecurityEvent({
      timestamp: new Date(base + index * 1000).toISOString(),
      category: "authentication",
      source: "sshd",
      type: "login-attempt",
      details: {
        outcome: "failure",
        sourceIp: "203.0.113.50",
        username: "admin",
      },
    }));
  }

  events.push(new SecurityEvent({
    timestamp: new Date(base + 10000).toISOString(),
    category: "authentication",
    source: "sshd",
    type: "login-attempt",
    details: {
      outcome: "success",
      sourceIp: "203.0.113.50",
      username: "admin",
      precedingFailures: 6,
    },
  }));

  events.push(new SecurityEvent({
    timestamp: new Date(base + 11000).toISOString(),
    category: "network",
    source: "ss",
    type: "listener",
    details: {
      state: "LISTEN",
      protocol: "tcp",
      local: "0.0.0.0:2375",
      pid: 810,
      process: "dockerd",
    },
  }));

  return events;
}

function main() {
  const processor = new EventProcessor();
  const events = buildDemoEvents();

  for (const event of events) processor.ingest(event);

  // Authentication correlation runs as a batch because preceding-failure
  // counts depend on event order within a defined observation window.
  processor.addAlerts(analyzeAuthentication(events));

  const report = {
    generatedAt: new Date().toISOString(),
    mode: "synthetic-demo",
    summary: processor.summary(),
    alerts: processor.getAlerts().map((alert) => ({
      severity: alert.severity,
      title: alert.title,
      evidence: alert.evidence,
      recommendation: alert.recommendation,
    })),
  };

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`Monitoring failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  Alert,
  EventProcessor,
  SecurityEvent,
  analyzeAuthentication,
  analyzeListener,
  parseEndpoint,
};
