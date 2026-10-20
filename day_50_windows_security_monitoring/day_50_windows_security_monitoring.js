"use strict";

/*
 * Windows Security Monitoring
 *
 * This program models normalized Windows Security events and evaluates them
 * through independent detection rules. It is intentionally event-driven:
 * events are emitted, retained in a bounded in-memory stream, and evaluated
 * by subscribed detectors.
 */

const fs = require("node:fs/promises");
const readline = require("node:readline");

const EVENT_NAMES = new Map([
  [4624, "successful_logon"],
  [4625, "failed_logon"],
  [4634, "logoff"],
  [4647, "user_initiated_logoff"],
  [4672, "special_privileges_assigned"],
  [4688, "process_created"],
  [4720, "account_created"],
  [4722, "account_enabled"],
  [4725, "account_disabled"],
  [4726, "account_deleted"],
  [4738, "account_changed"],
  [4740, "account_locked"],
]);

const SCRIPT_INTERPRETERS = new Set([
  "powershell.exe",
  "cmd.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "certutil.exe",
]);

function parseTimestamp(value) {
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    throw new Error(`Invalid timestamp: ${value}`);
  }
  return timestamp;
}

function validateIPv4(value) {
  if (value == null || value === "") return;

  const octets = value.split(".");
  if (octets.length !== 4 || octets.some((x) => !/^\d+$/.test(x))) {
    throw new Error(`Invalid IPv4 address: ${value}`);
  }

  if (octets.some((x) => Number(x) < 0 || Number(x) > 255)) {
    throw new Error(`Invalid IPv4 address: ${value}`);
  }
}

class SecurityEvent {
  constructor(input) {
    if (!Number.isInteger(input.eventId) || input.eventId <= 0) {
      throw new Error("eventId must be a positive integer");
    }

    if (!input.computer || !input.subjectUser) {
      throw new Error("computer and subjectUser are required");
    }

    validateIPv4(input.sourceIp);

    this.eventId = input.eventId;
    this.timestamp = parseTimestamp(input.timestamp);
    this.computer = input.computer;
    this.subjectUser = input.subjectUser;
    this.targetUser = input.targetUser || null;
    this.sourceIp = input.sourceIp || null;
    this.processName = input.processName
      ? input.processName.toLowerCase()
      : null;
    this.processId = input.processId ?? null;
    this.logonType = input.logonType ?? null;
    this.privilege = input.privilege || null;
    this.message = input.message || "";
  }

  get kind() {
    return EVENT_NAMES.get(this.eventId) || "other";
  }
}

class SecurityEventStream {
  constructor(maxEvents = 10000) {
    if (!Number.isInteger(maxEvents) || maxEvents < 1) {
      throw new Error("maxEvents must be a positive integer");
    }

    this.maxEvents = maxEvents;
    this.events = [];
    this.listeners = new Set();
  }

  subscribe(listener) {
    if (typeof listener !== "function") {
      throw new TypeError("listener must be a function");
    }

    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  publish(event) {
    if (!(event instanceof SecurityEvent)) {
      throw new TypeError("publish expects SecurityEvent");
    }

    this.events.push(event);
    if (this.events.length > this.maxEvents) {
      this.events.shift();
    }

    for (const listener of this.listeners) {
      listener(event, this.events);
    }
  }
}

class SecurityMonitor {
  constructor() {
    this.alerts = [];
    this.failedLogons = new Map();
  }

  attach(stream) {
    stream.subscribe((event, history) => {
      this.processEvent(event, history);
    });
  }

  addAlert(severity, rule, event, evidence) {
    this.alerts.push({
      severity,
      rule,
      timestamp: new Date(event.timestamp).toISOString(),
      computer: event.computer,
      user: event.targetUser || event.subjectUser,
      evidence,
    });
  }

  processEvent(event, history) {
    if (event.eventId === 4625) {
      this.handleFailedLogon(event);
    }

    if (event.eventId === 4672) {
      const severity = event.privilege?.toLowerCase().includes("debug")
        ? "high"
        : "medium";

      this.addAlert(
        severity,
        "special_privilege_assignment",
        event,
        event.privilege || "special privilege"
      );
    }

    if (event.eventId === 4688 &&
        SCRIPT_INTERPRETERS.has(event.processName)) {
      this.addAlert(
        "medium",
        "administrative_or_script_interpreter_process",
        event,
        `${event.processName} PID=${event.processId ?? "unknown"}`
      );
    }

    if ([4720, 4722, 4725, 4726, 4738].includes(event.eventId)) {
      this.addAlert(
        [4720, 4722].includes(event.eventId) ? "high" : "medium",
        "account_activity",
        event,
        `${event.kind}: target=${event.targetUser || "unknown"}`
      );
    }

    if (
      event.eventId === 4624 &&
      [2, 10, 11].includes(event.logonType) &&
      ["administrator", "admin"].includes(
        (event.targetUser || event.subjectUser).toLowerCase()
      )
    ) {
      this.addAlert(
        "high",
        "privileged_interactive_logon",
        event,
        `logonType=${event.logonType}, source=${event.sourceIp || "unknown"}`
      );
    }

    this.detectCorrelatedActivity(event, history);
  }

  handleFailedLogon(event) {
    const user = event.targetUser || event.subjectUser;

    if (!this.failedLogons.has(user)) {
      this.failedLogons.set(user, []);
    }

    const entries = this.failedLogons.get(user);
    entries.push(event);

    const windowMs = 5 * 60 * 1000;
    const cutoff = event.timestamp - windowMs;

    while (entries.length && entries[0].timestamp < cutoff) {
      entries.shift();
    }

    if (entries.length >= 3) {
      this.addAlert(
        "high",
        "failed_logon_burst",
        event,
        `${entries.length} failed logons for ${user} within five minutes`
      );
      entries.length = 0;
    }
  }

  detectCorrelatedActivity(event, history) {
    if (event.eventId !== 4688) return;

    const recentPrivilege = history.findLast(
      (item) =>
        item.eventId === 4672 &&
        item.computer === event.computer &&
        item.subjectUser === event.subjectUser &&
        event.timestamp - item.timestamp <= 60_000
    );

    if (recentPrivilege) {
      this.addAlert(
        "high",
        "privilege_then_process",
        event,
        `${recentPrivilege.privilege || "special privilege"} followed by ${event.processName}`
      );
    }
  }
}

async function readJsonLines(file) {
  const input = require("node:fs").createReadStream(file, {
    encoding: "utf8",
  });

  const reader = readline.createInterface({
    input,
    crlfDelay: Infinity,
  });

  const events = [];

  for await (const line of reader) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    events.push(new SecurityEvent(JSON.parse(trimmed)));
  }

  return events;
}

function sampleEvents() {
  const base = Date.parse("2026-10-20T05:00:00Z");

  const raw = [
    {
      eventId: 4624,
      offset: 0,
      computer: "WS-01",
      subjectUser: "SYSTEM",
      targetUser: "alice",
      sourceIp: "10.10.1.20",
      logonType: 2,
    },
    {
      eventId: 4688,
      offset: 60,
      computer: "WS-01",
      subjectUser: "alice",
      processName: "powershell.exe",
      processId: 2120,
    },
    {
      eventId: 4672,
      offset: 120,
      computer: "WS-01",
      subjectUser: "alice",
      privilege: "SeDebugPrivilege",
    },
    {
      eventId: 4688,
      offset: 150,
      computer: "WS-01",
      subjectUser: "alice",
      processName: "cmd.exe",
      processId: 2200,
    },
    {
      eventId: 4625,
      offset: 180,
      computer: "WS-01",
      subjectUser: "bob",
      targetUser: "administrator",
      sourceIp: "10.10.1.90",
      logonType: 10,
    },
    {
      eventId: 4625,
      offset: 240,
      computer: "WS-01",
      subjectUser: "bob",
      targetUser: "administrator",
      sourceIp: "10.10.1.90",
      logonType: 10,
    },
    {
      eventId: 4625,
      offset: 300,
      computer: "WS-01",
      subjectUser: "bob",
      targetUser: "administrator",
      sourceIp: "10.10.1.90",
      logonType: 10,
    },
    {
      eventId: 4720,
      offset: 420,
      computer: "DC-01",
      subjectUser: "admin",
      targetUser: "backupsvc",
    },
  ];

  return raw.map((event) => ({
    ...event,
    timestamp: new Date(base + event.offset * 1000).toISOString(),
  }));
}

async function main() {
  const file = process.argv[2];
  const inputs = file
    ? await readJsonLines(file)
    : sampleEvents().map((item) => new SecurityEvent(item));

  const stream = new SecurityEventStream();
  const monitor = new SecurityMonitor();
  monitor.attach(stream);

  for (const event of inputs) {
    stream.publish(event);
  }

  console.log("WINDOWS SECURITY MONITOR");
  console.log("========================");
  console.log(`Events analyzed: ${stream.events.length}`);

  const counts = new Map();
  for (const event of stream.events) {
    counts.set(event.kind, (counts.get(event.kind) || 0) + 1);
  }

  console.log("\nEvent types:");
  for (const [kind, count] of counts) {
    console.log(`  ${kind}: ${count}`);
  }

  console.log("\nAlerts:");
  if (monitor.alerts.length === 0) {
    console.log("  No detection rules triggered.");
  } else {
    for (const alert of monitor.alerts) {
      console.log(
        `  [${alert.severity.toUpperCase()}] ` +
        `${alert.timestamp} ${alert.computer} ${alert.user} ` +
        `${alert.rule}: ${alert.evidence}`
      );
    }
  }
}

main().catch((error) => {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 1;
});
