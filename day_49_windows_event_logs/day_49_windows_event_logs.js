"use strict";

/*
 * Windows Event Logs with Node.js
 *
 * This implementation treats Windows event collection as an asynchronous,
 * event-driven pipeline. It uses PowerShell's Get-WinEvent rather than
 * third-party npm packages, then performs log-specific normalization and
 * authentication analysis.
 *
 * Run on Windows with:
 *   node windows-event-logs.js
 */

const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

const LOGS = {
  security: "Security",
  system: "System",
  application: "Application",
  powershell: "Microsoft-Windows-PowerShell/Operational",
};

const AUTH_EVENTS = new Map([
  [4624, "successful_logon"],
  [4625, "failed_logon"],
  [4634, "logoff"],
  [4647, "user_initiated_logoff"],
  [4672, "special_privileges_assigned"],
  [4768, "kerberos_tgt_requested"],
  [4769, "kerberos_service_ticket_requested"],
  [4771, "kerberos_pre_authentication_failed"],
  [4776, "ntlm_authentication"],
]);

const POWERSHELL_EVENTS = new Map([
  [400, "engine_started"],
  [403, "engine_stopped"],
  [4103, "module_logging"],
  [4104, "script_block_logging"],
  [4105, "command_started"],
  [4106, "command_stopped"],
]);

const SECURITY_EVENTS = new Map([
  [1102, "audit_log_cleared"],
  [4720, "account_created"],
  [4728, "global_security_group_membership_changed"],
  [4732, "local_security_group_membership_changed"],
  [7045, "service_installed"],
]);

function parseEventXml(xml) {
  const text = String(xml);

  const value = (tag, attribute = null) => {
    const expression = attribute
      ? new RegExp(`<${tag}[^>]*${attribute}="([^"]*)"`, "i")
      : new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i");

    const match = text.match(expression);
    return match ? match[1] : null;
  };

  const eventId = Number(value("EventID") || 0);
  const recordId = Number(value("EventRecordID") || 0);
  const systemTime = value("TimeCreated", "SystemTime");
  const provider = value("Provider", "Name") || "Unknown";
  const computer = value("Computer") || "Unknown";

  const data = {};
  const dataRegex = /<Data\s+Name="([^"]*)">(.*?)<\/Data>/gis;

  for (const match of text.matchAll(dataRegex)) {
    data[match[1]] = match[2].replace(/&lt;/g, "<").replace(/&gt;/g, ">");
  }

  return {
    recordId,
    eventId,
    provider,
    computer,
    timestamp: systemTime ? new Date(systemTime) : null,
    user: data.TargetUserName || data.SubjectUserName || null,
    ipAddress: data.IpAddress || data.ClientAddress || null,
    data,
    rawXml: text,
  };
}

async function queryWindowsLog(logName, count = 50) {
  /*
   * Get-WinEvent returns native Event objects. ConvertTo-Xml preserves
   * EventData fields, allowing the JavaScript layer to retain fields such
   * as TargetUserName and IpAddress instead of parsing human-readable text.
   */
  const script = `
    Get-WinEvent -LogName '${logName.replaceAll("'", "''")}' -MaxEvents ${count} |
      ForEach-Object { $_.ToXml() }
  `;

  const { stdout } = await execFileAsync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    {
      windowsHide: true,
      maxBuffer: 32 * 1024 * 1024,
    }
  );

  const documents = stdout
    .split(/(?=<Event xmlns=)/i)
    .map((item) => item.trim())
    .filter(Boolean);

  return documents.map((xml) => ({
    logName,
    ...parseEventXml(xml),
  }));
}

function classifyEvent(event) {
  if (AUTH_EVENTS.has(event.eventId)) {
    return {
      category: "authentication",
      name: AUTH_EVENTS.get(event.eventId),
    };
  }

  if (POWERSHELL_EVENTS.has(event.eventId)) {
    return {
      category: "powershell",
      name: POWERSHELL_EVENTS.get(event.eventId),
    };
  }

  if (SECURITY_EVENTS.has(event.eventId)) {
    return {
      category: "security",
      name: SECURITY_EVENTS.get(event.eventId),
    };
  }

  if (event.logName === LOGS.system) {
    return { category: "system", name: `system_event_${event.eventId}` };
  }

  if (event.logName === LOGS.application) {
    return { category: "application", name: `application_event_${event.eventId}` };
  }

  return { category: "unknown", name: `event_${event.eventId}` };
}

function authenticationReport(events) {
  const users = new Map();

  for (const event of events) {
    if (!AUTH_EVENTS.has(event.eventId)) continue;

    const user = event.user || "unknown";
    if (!users.has(user)) {
      users.set(user, {
        successful: 0,
        failed: 0,
        privileged: 0,
        sources: new Set(),
      });
    }

    const record = users.get(user);

    if (event.eventId === 4624) record.successful += 1;
    if (event.eventId === 4625) record.failed += 1;
    if (event.eventId === 4672) record.privileged += 1;
    if (event.ipAddress) record.sources.add(event.ipAddress);
  }

  return [...users.entries()].map(([user, record]) => ({
    user,
    successful: record.successful,
    failed: record.failed,
    privileged: record.privileged,
    sources: [...record.sources],
  }));
}

function detectBruteForce(events, threshold = 5, windowMs = 5 * 60 * 1000) {
  const failures = events
    .filter((event) => event.eventId === 4625 && event.ipAddress)
    .sort((a, b) => a.timestamp - b.timestamp);

  const findings = [];

  for (let start = 0; start < failures.length; start += 1) {
    const source = failures[start].ipAddress;
    const user = failures[start].user || "unknown";
    let end = start;

    while (
      end < failures.length &&
      failures[end].ipAddress === source &&
      failures[end].user === user &&
      failures[end].timestamp - failures[start].timestamp <= windowMs
    ) {
      end += 1;
    }

    if (end - start >= threshold) {
      findings.push({
        user,
        source,
        attempts: end - start,
        firstSeen: failures[start].timestamp.toISOString(),
        lastSeen: failures[end - 1].timestamp.toISOString(),
      });
      start = end - 1;
    }
  }

  return findings;
}

function powershellReport(events) {
  const records = events.filter(
    (event) => event.logName === LOGS.powershell
  );

  return {
    total: records.length,
    scriptBlockLogging: records.filter((event) => event.eventId === 4104).length,
    commandStarts: records.filter((event) => event.eventId === 4105).length,
    engineStarts: records.filter((event) => event.eventId === 400).length,
    users: [...new Set(records.map((event) => event.user).filter(Boolean))],
  };
}

function suspiciousEvents(events) {
  return events
    .filter((event) => SECURITY_EVENTS.has(event.eventId))
    .map((event) => ({
      eventId: event.eventId,
      eventName: SECURITY_EVENTS.get(event.eventId),
      user: event.user,
      ipAddress: event.ipAddress,
      timestamp: event.timestamp?.toISOString() ?? null,
    }));
}

async function main() {
  if (process.platform !== "win32") {
    console.error("This live collector requires Windows.");
    process.exitCode = 1;
    return;
  }

  const count = Number.parseInt(process.env.EVENT_COUNT || "30", 10);

  /*
   * Promise.all is useful here because the four event logs are independent.
   * Collection happens concurrently, while each Get-WinEvent invocation
   * remains isolated so one inaccessible log does not destroy all results.
   */
  const results = await Promise.allSettled(
    Object.values(LOGS).map((logName) => queryWindowsLog(logName, count))
  );

  const events = [];
  const failures = [];

  for (const result of results) {
    if (result.status === "fulfilled") {
      events.push(...result.value);
    } else {
      failures.push(result.reason instanceof Error
        ? result.reason.message
        : String(result.reason));
    }
  }

  const categories = new Map();

  for (const event of events) {
    const classification = classifyEvent(event);
    categories.set(
      classification.category,
      (categories.get(classification.category) || 0) + 1
    );
  }

  console.log("Windows Event Log Operational Report");
  console.log("=====================================");
  console.log(`Events collected: ${events.length}`);
  console.log("Categories:", Object.fromEntries(categories));

  console.log("\nAuthentication:");
  console.table(authenticationReport(events));

  console.log("\nPowerShell telemetry:");
  console.dir(powershellReport(events), { depth: null });

  console.log("\nSecurity-sensitive events:");
  console.table(suspiciousEvents(events));

  console.log("\nPotential authentication bursts:");
  console.table(detectBruteForce(events));

  if (failures.length) {
    console.log("\nLog collection failures:");
    for (const failure of failures) {
      console.log(`- ${failure}`);
    }
  }

  /*
   * Security boundary: event data is evidence. Do not execute command text
   * found in EventData, and do not pass event messages into a shell.
   */
}

main().catch((error) => {
  console.error(`Fatal collection error: ${error.message}`);
  process.exitCode = 1;
});
