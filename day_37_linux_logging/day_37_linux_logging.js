#!/usr/bin/env node

/*
 * Linux Logging Laboratory for Node.js
 *
 * Demonstrates:
 * - syslog facilities and severities
 * - journald access through journalctl
 * - authentication-log analysis
 * - kernel-log classification
 * - application logging
 * - event-driven log processing
 * - structured JSON logging
 * - correlation and security-oriented detection
 *
 * The program uses only Node.js built-ins.
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { EventEmitter } = require("events");

const SEVERITIES = Object.freeze({
  emerg: 0,
  alert: 1,
  crit: 2,
  err: 3,
  warning: 4,
  notice: 5,
  info: 6,
  debug: 7,
});

const FACILITIES = Object.freeze({
  kern: 0,
  user: 1,
  mail: 2,
  daemon: 3,
  auth: 4,
  syslog: 5,
  lpr: 6,
  news: 7,
  uucp: 8,
  cron: 9,
  authpriv: 10,
  ftp: 11,
  local0: 16,
  local1: 17,
  local2: 18,
  local3: 19,
  local4: 20,
  local5: 21,
  local6: 22,
  local7: 23,
});

class LogRecord {
  constructor({
    timestamp = new Date(),
    host = os.hostname(),
    service = "unknown",
    facility = "daemon",
    severity = "info",
    message = "",
    source = "unknown",
    pid = null,
    user = null,
    ip = null,
  }) {
    this.timestamp = timestamp;
    this.host = host;
    this.service = service;
    this.facility = facility;
    this.severity = severity;
    this.message = message;
    this.source = source;
    this.pid = pid;
    this.user = user;
    this.ip = ip;
  }

  priority() {
    return (
      (FACILITIES[this.facility] ?? 1) * 8 +
      (SEVERITIES[this.severity] ?? 6)
    );
  }

  toJSON() {
    return {
      timestamp: this.timestamp.toISOString(),
      host: this.host,
      service: this.service,
      facility: this.facility,
      severity: this.severity,
      message: this.message,
      source: this.source,
      pid: this.pid,
      user: this.user,
      ip: this.ip,
    };
  }
}

class SyslogParser {
  parse(line, source = "syslog") {
    const match = line.match(
      /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:[]+)(?:\[(\d+)\])?:\s*(.*)$/
    );

    if (!match) {
      return null;
    }

    const [, month, day, time, host, service, pid, message] = match;
    const now = new Date();
    const timestamp = new Date(
      `${month} ${day}, ${now.getUTCFullYear()} ${time} UTC`
    );

    const facility =
      service === "sshd" || service === "sudo" ? "authpriv" : "daemon";

    return new LogRecord({
      timestamp,
      host,
      service,
      facility,
      severity: inferSeverity(message),
      message,
      source,
      pid: pid ? Number(pid) : null,
      ip: extractIp(message),
      user: extractUser(message),
    });
  }
}

function inferSeverity(message) {
  const text = message.toLowerCase();

  if (text.includes("kernel panic") || text.includes("emergency")) {
    return "emerg";
  }

  if (text.includes("critical") || text.includes("panic")) {
    return "crit";
  }

  if (
    text.includes("error") ||
    text.includes("failed") ||
    text.includes("failure")
  ) {
    return "err";
  }

  if (text.includes("warning") || text.includes("warn")) {
    return "warning";
  }

  return "info";
}

function extractIp(message) {
  const match = message.match(
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/
  );
  return match ? match[0] : null;
}

function extractUser(message) {
  const match = message.match(
    /(?:for|user)\s+(?:invalid user\s+)?([A-Za-z0-9._-]+)/
  );
  return match ? match[1] : null;
}

class JournalReader {
  available() {
    if (process.platform !== "linux") {
      return false;
    }

    try {
      execFileSync("journalctl", ["--version"], {
        stdio: "ignore",
      });
      return true;
    } catch {
      return false;
    }
  }

  recent(limit = 10) {
    if (!this.available()) {
      return [];
    }

    try {
      const output = execFileSync(
        "journalctl",
        ["-n", String(limit), "--no-pager", "-o", "json"],
        {
          encoding: "utf8",
          timeout: 10000,
        }
      );

      return output
        .split("\n")
        .filter(Boolean)
        .flatMap((line) => {
          try {
            const item = JSON.parse(line);
            const priority = Number(item.PRIORITY ?? 6);
            const facilityNumber = Number(
              item.SYSLOG_FACILITY ?? 3
            );

            const facility =
              Object.entries(FACILITIES).find(
                ([, value]) => value === facilityNumber
              )?.[0] ?? "daemon";

            const severity =
              Object.entries(SEVERITIES).find(
                ([, value]) => value === priority
              )?.[0] ?? "info";

            return [
              new LogRecord({
                timestamp: new Date(
                  Number(item.__REALTIME_TIMESTAMP ?? Date.now() * 1000) /
                    1000
                ),
                host: item._HOSTNAME ?? os.hostname(),
                service:
                  item._SYSTEMD_UNIT ??
                  item.SYSLOG_IDENTIFIER ??
                  "systemd",
                facility,
                severity,
                message: String(item.MESSAGE ?? ""),
                source: "journald",
                pid: item._PID ? Number(item._PID) : null,
              }),
            ];
          } catch {
            return [];
          }
        });
    } catch {
      return [];
    }
  }
}

class AuthenticationAnalyzer {
  analyze(records) {
    const failures = new Map();
    const successfulUsers = new Map();

    for (const record of records) {
      if (!["sshd", "ssh"].includes(record.service)) {
        continue;
      }

      if (
        /Failed password|Invalid user|authentication failure/i.test(
          record.message
        )
      ) {
        const ip = record.ip ?? extractIp(record.message);
        if (ip) {
          failures.set(ip, (failures.get(ip) ?? 0) + 1);
        }
      }

      const success = record.message.match(
        /Accepted .*? for (\S+) from ([0-9a-fA-F:.]+)/
      );

      if (success) {
        const user = success[1];
        successfulUsers.set(
          user,
          (successfulUsers.get(user) ?? 0) + 1
        );
      }
    }

    return {
      failures: Object.fromEntries(failures),
      successfulUsers: Object.fromEntries(successfulUsers),
      suspiciousIps: Object.fromEntries(
        [...failures.entries()].filter(([, count]) => count >= 3)
      ),
    };
  }
}

class KernelAnalyzer {
  classify(records) {
    const categories = new Map();

    const keywords = {
      memory: ["oom", "out of memory", "memory"],
      storage: ["i/o error", "filesystem", "ext4", "xfs", "nvme"],
      network: ["link is down", "link is up", "network"],
      hardware: ["thermal", "cpu", "hardware", "firmware"],
      security: ["apparmor", "selinux", "audit", "denied"],
    };

    for (const record of records) {
      if (
        record.facility !== "kern" &&
        !["kernel", "kernel:kernel"].includes(record.service)
      ) {
        continue;
      }

      const text = record.message.toLowerCase();
      let matched = false;

      for (const [category, terms] of Object.entries(keywords)) {
        if (terms.some((term) => text.includes(term))) {
          if (!categories.has(category)) {
            categories.set(category, []);
          }
          categories.get(category).push(record.message);
          matched = true;
        }
      }

      if (!matched) {
        if (!categories.has("other")) {
          categories.set("other", []);
        }
        categories.get("other").push(record.message);
      }
    }

    return Object.fromEntries(categories);
  }
}

class LogEventBus extends EventEmitter {
  publish(record) {
    this.emit("log", record);

    if (record.severity === "err" || record.severity === "crit") {
      this.emit("error-level", record);
    }

    if (record.service === "sshd") {
      this.emit("authentication", record);
    }

    if (record.facility === "kern") {
      this.emit("kernel", record);
    }
  }
}

class ApplicationLogger {
  constructor(filePath) {
    this.filePath = filePath;
  }

  write({
    level = "info",
    service,
    message,
    requestId,
    user = null,
    ip = null,
  }) {
    /*
     * Structured application logs make downstream parsing reliable.
     * Credentials and session secrets must never be written here.
     */
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      service,
      message,
      requestId,
      user,
      ip,
      pid: process.pid,
    };

    fs.appendFileSync(
      this.filePath,
      `${JSON.stringify(entry)}\n`,
      "utf8"
    );
  }
}

function simulatedRecords() {
  const base = new Date();

  return [
    new LogRecord({
      timestamp: new Date(base.getTime()),
      host: "server01",
      service: "sshd",
      facility: "authpriv",
      severity: "warning",
      message:
        "Failed password for invalid user admin from 203.0.113.42 port 44221 ssh2",
      source: "/var/log/auth.log",
      ip: "203.0.113.42",
      user: "admin",
    }),
    new LogRecord({
      timestamp: new Date(base.getTime() + 15_000),
      host: "server01",
      service: "sshd",
      facility: "authpriv",
      severity: "warning",
      message:
        "Failed password for root from 203.0.113.42 port 44222 ssh2",
      source: "/var/log/auth.log",
      ip: "203.0.113.42",
      user: "root",
    }),
    new LogRecord({
      timestamp: new Date(base.getTime() + 30_000),
      host: "server01",
      service: "sshd",
      facility: "authpriv",
      severity: "info",
      message:
        "Accepted publickey for deploy from 10.10.20.15 port 51000 ssh2",
      source: "/var/log/auth.log",
      ip: "10.10.20.15",
      user: "deploy",
    }),
    new LogRecord({
      timestamp: new Date(base.getTime() + 45_000),
      host: "server01",
      service: "kernel",
      facility: "kern",
      severity: "err",
      message: "nvme0: I/O error, aborting command",
      source: "/var/log/kern.log",
    }),
    new LogRecord({
      timestamp: new Date(base.getTime() + 60_000),
      host: "server01",
      service: "kernel",
      facility: "kern",
      severity: "warning",
      message: "Out of memory: Kill process 2481 (worker)",
      source: "/var/log/kern.log",
      pid: 2481,
    }),
    new LogRecord({
      timestamp: new Date(base.getTime() + 75_000),
      host: "server01",
      service: "inventory-api",
      facility: "local0",
      severity: "err",
      message: "database connection pool exhausted",
      source: "/var/log/inventory-api.json",
      ip: "203.0.113.42",
    }),
  ];
}

function correlate(records, windowMs = 120_000) {
  const failures = records.filter(
    (record) =>
      record.service === "sshd" &&
      record.ip &&
      /Failed password/i.test(record.message)
  );

  const applicationEvents = records.filter(
    (record) =>
      record.service !== "sshd" &&
      record.service !== "kernel" &&
      record.ip
  );

  return failures.flatMap((failure) =>
    applicationEvents
      .filter((event) => event.ip === failure.ip)
      .filter(
        (event) =>
          Math.abs(
            event.timestamp.getTime() - failure.timestamp.getTime()
          ) <= windowMs
      )
      .map((event) => ({
        ip: failure.ip,
        authenticationEvent: failure.message,
        applicationEvent: event.message,
      }))
  );
}

function demonstrateApplicationLogging() {
  const filePath = path.join(
    os.tmpdir(),
    `linux-logging-${process.pid}.jsonl`
  );

  const logger = new ApplicationLogger(filePath);

  logger.write({
    level: "info",
    service: "inventory-api",
    message: "request completed",
    requestId: "req-8f12",
    user: "analyst",
    ip: "192.0.2.10",
  });

  logger.write({
    level: "error",
    service: "inventory-api",
    message: "database connection failed",
    requestId: "req-8f13",
    ip: "192.0.2.11",
  });

  console.log("\nAPPLICATION LOGGING");
  console.log("-".repeat(60));
  console.log(fs.readFileSync(filePath, "utf8").trim());

  fs.unlinkSync(filePath);
}

function printReport(records) {
  const severityCounts = new Map();
  const serviceCounts = new Map();

  for (const record of records) {
    severityCounts.set(
      record.severity,
      (severityCounts.get(record.severity) ?? 0) + 1
    );

    serviceCounts.set(
      record.service,
      (serviceCounts.get(record.service) ?? 0) + 1
    );
  }

  console.log("\nLOGGING REPORT");
  console.log("-".repeat(60));
  console.log(`Records: ${records.length}`);

  console.log("Severities:");
  for (const [severity, count] of [...severityCounts.entries()].sort(
    (a, b) => SEVERITIES[a[0]] - SEVERITIES[b[0]]
  )) {
    console.log(`  ${severity}: ${count}`);
  }

  console.log("Services:");
  for (const [service, count] of [...serviceCounts.entries()].sort(
    (a, b) => b[1] - a[1]
  )) {
    console.log(`  ${service}: ${count}`);
  }
}

function demonstrateEventDrivenProcessing(records) {
  console.log("\nEVENT-DRIVEN LOG PROCESSING");
  console.log("-".repeat(60));

  const bus = new LogEventBus();

  bus.on("authentication", (record) => {
    console.log(
      `[AUTH] ${record.severity}: ${record.message}`
    );
  });

  bus.on("kernel", (record) => {
    console.log(`[KERNEL] ${record.message}`);
  });

  bus.on("error-level", (record) => {
    console.log(
      `[ERROR PIPELINE] ${record.service}: ${record.message}`
    );
  });

  for (const record of records) {
    bus.publish(record);
  }
}

function main() {
  console.log("LINUX LOGGING LABORATORY");
  console.log("=".repeat(60));
  console.log(`Host: ${os.hostname()}`);
  console.log(`Platform: ${process.platform}`);

  console.log("\nSYSLOG PRIORITY MODEL");
  console.log("-".repeat(60));

  for (const [facility, severity] of [
    ["authpriv", "warning"],
    ["kern", "err"],
    ["local0", "info"],
  ]) {
    const priority =
      FACILITIES[facility] * 8 + SEVERITIES[severity];

    console.log(
      `${facility.padEnd(10)} ${severity.padEnd(8)} priority=${priority}`
    );
  }

  const parser = new SyslogParser();
  const sample = parser.parse(
    "Oct  7 16:30:22 server01 sshd[7124]: Failed password for root from 203.0.113.42 port 4422 ssh2",
    "/var/log/auth.log"
  );

  console.log("\nPARSED AUTHENTICATION RECORD");
  console.log("-".repeat(60));
  console.log(JSON.stringify(sample, null, 2));

  const records = simulatedRecords();

  const auth = new AuthenticationAnalyzer().analyze(records);
  console.log("\nAUTHENTICATION ANALYSIS");
  console.log("-".repeat(60));
  console.log(JSON.stringify(auth, null, 2));

  const kernel = new KernelAnalyzer().classify(records);
  console.log("\nKERNEL ANALYSIS");
  console.log("-".repeat(60));
  console.log(JSON.stringify(kernel, null, 2));

  const correlations = correlate(records);
  console.log("\nCROSS-SOURCE CORRELATION");
  console.log("-".repeat(60));
  console.log(JSON.stringify(correlations, null, 2));

  demonstrateEventDrivenProcessing(records);
  demonstrateApplicationLogging();
  printReport(records);

  const journal = new JournalReader();
  console.log("\nJOURNALD");
  console.log("-".repeat(60));

  if (!journal.available()) {
    console.log(
      "journalctl is unavailable on this host. On a systemd system, " +
        "journalctl queries structured records collected by journald."
    );
  } else {
    const entries = journal.recent(5);
    for (const entry of entries) {
      console.log(
        `${entry.timestamp.toISOString()} ` +
          `${entry.service} ${entry.severity} ${entry.message}`
      );
    }
  }
}

main();
