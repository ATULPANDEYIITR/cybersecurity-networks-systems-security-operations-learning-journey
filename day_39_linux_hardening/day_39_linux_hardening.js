"use strict";

/*
 * Linux hardening policy engine.
 *
 * Demonstrates an event-driven remediation workflow using Node.js standard
 * libraries. The model is deliberately read-only: it never changes accounts,
 * firewall rules, packages, SSH configuration, or audit settings on the host.
 *
 * Run:
 *   node linux-hardening.js
 *   node linux-hardening.js --json
 *   node linux-hardening.js --test
 */

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");

const severityRank = Object.freeze({
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
});

class Finding {
  constructor({ id, category, severity, title, evidence, remediation }) {
    if (!id || !category || !title || !evidence || !remediation) {
      throw new TypeError("A finding requires an ID, category, title, evidence, and remediation.");
    }
    if (!(severity in severityRank)) {
      throw new TypeError(`Unsupported severity: ${severity}`);
    }

    this.id = id;
    this.category = category;
    this.severity = severity;
    this.title = title;
    this.evidence = evidence;
    this.remediation = remediation;
    Object.freeze(this);
  }
}

function makeFinding(id, category, severity, title, evidence, remediation) {
  return new Finding({ id, category, severity, title, evidence, remediation });
}

function auditAccounts(accounts) {
  const findings = [];
  const usernames = new Set();
  const uids = new Map();

  for (const account of accounts) {
    if (!/^[a-z_][a-z0-9_-]{0,31}\$?$/.test(account.username)) {
      findings.push(makeFinding(
        "ACC-NAME", "accounts", "high",
        "Invalid local account name",
        String(account.username),
        "Review the account source and enforce a consistent naming policy."
      ));
    }

    if (usernames.has(account.username)) {
      findings.push(makeFinding(
        "ACC-DUPLICATE-NAME", "accounts", "high",
        "Duplicate account inventory entry",
        account.username,
        "Deduplicate the inventory and investigate provisioning."
      ));
    }
    usernames.add(account.username);

    if (uids.has(account.uid)) {
      findings.push(makeFinding(
        "ACC-DUPLICATE-UID", "accounts", "high",
        "UID collision",
        `${account.username} shares UID ${account.uid} with ${uids.get(account.uid)}.`,
        "Verify ownership and assign unique UIDs unless sharing is explicitly justified."
      ));
    } else {
      uids.set(account.uid, account.username);
    }

    if (account.uid === 0 && account.username !== "root") {
      findings.push(makeFinding(
        "ACC-UID0", "accounts", "critical",
        "Unexpected UID 0 account",
        account.username,
        "Investigate immediately and remove unintended superuser identity."
      ));
    }

    if (account.sudo && account.service) {
      findings.push(makeFinding(
        "ACC-SERVICE-SUDO", "accounts", "high",
        "Privileged service identity",
        account.username,
        "Remove unnecessary interactive privilege from service identities."
      ));
    }

    if (account.interactive && account.passwordLocked === false &&
        account.passwordMaxDays == null) {
      findings.push(makeFinding(
        "ACC-CREDENTIAL-LIFECYCLE", "accounts", "medium",
        "Credential lifecycle is undefined",
        account.username,
        "Define credential lifecycle and authentication controls based on risk."
      ));
    }
  }

  return findings;
}

function auditSsh(ssh) {
  const findings = [];

  if (ssh.permitRootLogin !== "no") {
    findings.push(makeFinding(
      "SSH-ROOT", "ssh", ssh.permitRootLogin === "yes" ? "critical" : "high",
      "Direct root login is not disabled",
      `PermitRootLogin=${ssh.permitRootLogin}`,
      "Set PermitRootLogin no and test administrative access before ending the current session."
    ));
  }

  if (ssh.passwordAuthentication) {
    findings.push(makeFinding(
      "SSH-PASSWORD", "ssh", "high",
      "SSH password authentication enabled",
      "PasswordAuthentication=yes",
      "Prefer managed public keys or another approved strong authentication mechanism."
    ));
  }

  if (!ssh.publicKeyAuthentication) {
    findings.push(makeFinding(
      "SSH-PUBKEY", "ssh", "high",
      "Public-key authentication disabled",
      "PubkeyAuthentication=no",
      "Enable an approved authentication method and validate recovery access."
    ));
  }

  if (!Array.isArray(ssh.allowedUsers) || ssh.allowedUsers.length === 0) {
    findings.push(makeFinding(
      "SSH-ALLOWLIST", "ssh", "medium",
      "SSH account allowlist missing",
      "No explicit allowed-user list is represented.",
      "Configure a reviewed account or group allowlist where operationally suitable."
    ));
  }

  if (!Number.isInteger(ssh.maxAuthTries) ||
      ssh.maxAuthTries < 1 || ssh.maxAuthTries > 4) {
    findings.push(makeFinding(
      "SSH-AUTH-TRIES", "ssh", "medium",
      "Authentication-attempt limit outside policy",
      String(ssh.maxAuthTries),
      "Set MaxAuthTries to a small positive value."
    ));
  }

  if (ssh.tcpForwarding) {
    findings.push(makeFinding(
      "SSH-FORWARDING", "ssh", "medium",
      "TCP forwarding is enabled",
      "AllowTcpForwarding=yes",
      "Disable forwarding unless required; restrict it for accounts that need it."
    ));
  }

  return findings;
}

function validateCidrOrAddress(value) {
  // This small validator deliberately supports IPv4 CIDR only. IPv6 policy
  // should use a tested IP-address library or the firewall's native parser.
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(value);
  if (!match) return false;

  const octets = match.slice(1, 5).map(Number);
  if (octets.some(octet => octet < 0 || octet > 255)) return false;

  const prefix = match[5] === undefined ? 32 : Number(match[5]);
  return prefix >= 0 && prefix <= 32;
}

function auditFirewall(firewall) {
  const findings = [];

  if (firewall.defaultInbound !== "deny" &&
      firewall.defaultInbound !== "reject") {
    findings.push(makeFinding(
      "FW-DEFAULT-IN", "firewall", "critical",
      "Inbound default policy is not restrictive",
      `Default inbound policy: ${firewall.defaultInbound}`,
      "Default to deny or reject and explicitly permit required services."
    ));
  }

  const signatures = new Set();

  for (const [index, rule] of firewall.rules.entries()) {
    if (!["inbound", "outbound", "forward"].includes(rule.direction)) {
      findings.push(makeFinding(
        "FW-DIRECTION", "firewall", "high",
        "Invalid firewall direction",
        `Rule ${index}: ${String(rule.direction)}`,
        "Use inbound, outbound, or forward."
      ));
      continue;
    }

    if (!["allow", "deny", "reject"].includes(rule.action)) {
      findings.push(makeFinding(
        "FW-ACTION", "firewall", "high",
        "Invalid firewall action",
        `Rule ${index}: ${String(rule.action)}`,
        "Use a supported firewall action."
      ));
      continue;
    }

    if (rule.port !== null &&
        (!Number.isInteger(rule.port) || rule.port < 1 || rule.port > 65535)) {
      findings.push(makeFinding(
        "FW-PORT", "firewall", "high",
        "Invalid transport port",
        `Rule ${index}: ${String(rule.port)}`,
        "Use an integer port from 1 through 65535 or null when no port applies."
      ));
      continue;
    }

    const signature = JSON.stringify([
      rule.direction, rule.action, rule.protocol, rule.port, rule.source
    ]);

    if (signatures.has(signature)) {
      findings.push(makeFinding(
        "FW-DUPLICATE", "firewall", "low",
        "Duplicate firewall rule",
        signature,
        "Review rule order and remove redundant entries."
      ));
    }
    signatures.add(signature);

    if (rule.direction === "inbound" && rule.action === "allow" &&
        rule.protocol === "tcp" && rule.port === 22 &&
        ["any", "0.0.0.0/0", "::/0"].includes(rule.source)) {
      findings.push(makeFinding(
        "FW-SSH-EXPOSED", "firewall", "high",
        "SSH is exposed to all sources",
        `Source: ${rule.source}`,
        "Restrict SSH to approved administrative networks or an access gateway."
      ));
    }

    if (rule.source !== "any" && rule.source !== "::/0" &&
        !validateCidrOrAddress(rule.source)) {
      findings.push(makeFinding(
        "FW-SOURCE", "firewall", "medium",
        "Firewall source is not a valid IPv4 address or CIDR",
        String(rule.source),
        "Validate the source using the native firewall parser and explicit IP-family rules."
      ));
    }
  }

  return findings;
}

function auditMaintenance(patch, audit) {
  const findings = [];

  if (patch.criticalPending > 0) {
    findings.push(makeFinding(
      "PATCH-CRITICAL", "patching", "critical",
      "Critical updates are pending",
      `${patch.criticalPending} critical updates`,
      "Prioritize affected packages, test the fixes, and apply them through change control."
    ));
  } else if (patch.securityPending > 0) {
    findings.push(makeFinding(
      "PATCH-SECURITY", "patching", "high",
      "Security updates are pending",
      `${patch.securityPending} security updates`,
      "Schedule installation based on severity, exposure, and the approved maintenance window."
    ));
  }

  if (patch.lastUpdateDays > 30) {
    findings.push(makeFinding(
      "PATCH-STALE", "patching", "high",
      "Patch inventory is stale",
      `${patch.lastUpdateDays} days since successful update`,
      "Investigate failed update jobs, repository connectivity, and patch cadence."
    ));
  }

  if (patch.rebootRequired) {
    findings.push(makeFinding(
      "PATCH-REBOOT", "patching", "high",
      "Restart is pending",
      "The package manager indicates a reboot is required.",
      "Schedule a controlled restart and validate application health."
    ));
  }

  if (!audit.auditdEnabled || !audit.persistentRules) {
    findings.push(makeFinding(
      "AUDIT-RULES", "auditing", "high",
      "Audit collection is incomplete",
      `auditd=${audit.auditdEnabled}, persistentRules=${audit.persistentRules}`,
      "Enable supported audit collection and persist reviewed audit rules."
    ));
  }

  if (!audit.authLogs || !audit.timeSync || !audit.fileIntegrity) {
    findings.push(makeFinding(
      "AUDIT-TELEMETRY", "auditing", "medium",
      "Security telemetry has gaps",
      `authLogs=${audit.authLogs}, timeSync=${audit.timeSync}, fileIntegrity=${audit.fileIntegrity}`,
      "Enable authentication logs, reliable time synchronization, and integrity monitoring."
    ));
  }

  return findings;
}

function evaluateServer(server) {
  const findings = [
    ...auditAccounts(server.accounts),
    ...auditSsh(server.ssh),
    ...auditFirewall(server.firewall),
    ...auditMaintenance(server.patch, server.audit),
  ];

  findings.sort((left, right) =>
    severityRank[left.severity] - severityRank[right.severity] ||
    left.category.localeCompare(right.category) ||
    left.id.localeCompare(right.id)
  );

  return findings;
}

class RemediationWorkflow extends EventEmitter {
  constructor(findings) {
    super();
    this.findings = new Map(findings.map(item => [item.id, item]));
    this.actions = new Map();
  }

  recordAction(findingId, action, actor) {
    const item = this.findings.get(findingId);
    if (!item) throw new Error(`Unknown finding: ${findingId}`);
    if (typeof actor !== "string" || actor.trim().length < 2) {
      throw new TypeError("A valid actor identity is required.");
    }
    if (!["accepted", "deferred", "not-applicable"].includes(action)) {
      throw new TypeError(`Unsupported remediation action: ${action}`);
    }

    const event = Object.freeze({
      findingId,
      action,
      actor: actor.trim(),
      timestamp: new Date().toISOString(),
      severity: item.severity,
    });

    this.actions.set(findingId, event);
    this.emit("remediation", event);
    return event;
  }

  unresolvedCriticalOrHigh() {
    return [...this.findings.values()].filter(item =>
      ["critical", "high"].includes(item.severity) &&
      !this.actions.has(item.id)
    );
  }
}

function exampleServer() {
  return {
    hostname: "api-prod-02",
    accounts: [
      {
        username: "root", uid: 0, passwordLocked: true,
        passwordMaxDays: null, interactive: true, sudo: true, service: false
      },
      {
        username: "platform", uid: 1000, passwordLocked: false,
        passwordMaxDays: 180, interactive: true, sudo: true, service: false
      },
      {
        username: "jobrunner", uid: 1001, passwordLocked: true,
        passwordMaxDays: null, interactive: true, sudo: true, service: true
      }
    ],
    ssh: {
      permitRootLogin: "no",
      passwordAuthentication: true,
      publicKeyAuthentication: true,
      maxAuthTries: 6,
      allowedUsers: ["platform", "jobrunner"],
      tcpForwarding: true
    },
    firewall: {
      defaultInbound: "allow",
      rules: [
        {
          direction: "inbound", action: "allow", protocol: "tcp",
          port: 22, source: "0.0.0.0/0"
        },
        {
          direction: "inbound", action: "allow", protocol: "tcp",
          port: 443, source: "0.0.0.0/0"
        }
      ]
    },
    patch: {
      criticalPending: 2,
      securityPending: 9,
      lastUpdateDays: 35,
      rebootRequired: true
    },
    audit: {
      auditdEnabled: false,
      persistentRules: false,
      authLogs: true,
      timeSync: true,
      fileIntegrity: false
    }
  };
}

function runTests() {
  assert.equal(validateCidrOrAddress("192.168.10.0/24"), true);
  assert.equal(validateCidrOrAddress("300.168.10.0/24"), false);
  assert.equal(validateCidrOrAddress("192.168.1.1/33"), false);

  const firewallFindings = auditFirewall({
    defaultInbound: "deny",
    rules: [{
      direction: "inbound", action: "allow", protocol: "tcp",
      port: 22, source: "0.0.0.0/0"
    }]
  });
  assert.ok(firewallFindings.some(item => item.id === "FW-SSH-EXPOSED"));

  assert.throws(() => new Finding({
    id: "bad", category: "ssh", severity: "unknown",
    title: "x", evidence: "y", remediation: "z"
  }), /Unsupported severity/);

  const workflow = new RemediationWorkflow([
    makeFinding("PATCH", "patching", "critical", "Pending patch", "evidence", "fix")
  ]);

  assert.equal(workflow.unresolvedCriticalOrHigh().length, 1);
  const observed = [];
  workflow.on("remediation", event => observed.push(event.action));
  workflow.recordAction("PATCH", "accepted", "security-operator");
  assert.deepEqual(observed, ["accepted"]);
  assert.equal(workflow.unresolvedCriticalOrHigh().length, 0);

  console.log("All JavaScript hardening tests passed.");
}

function main() {
  if (process.argv.includes("--test")) {
    runTests();
    return;
  }

  const server = exampleServer();
  const findings = evaluateServer(server);

  const counts = Object.fromEntries(
    Object.keys(severityRank).map(severity => [
      severity,
      findings.filter(item => item.severity === severity).length
    ])
  );

  const report = {
    hostname: server.hostname,
    assessedAt: new Date().toISOString(),
    findingCount: findings.length,
    severityCounts: counts,
    findings
  };

  if (process.argv.includes("--json")) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    console.log(`Linux hardening assessment: ${server.hostname}`);
    console.log(JSON.stringify(counts, null, 2));

    for (const item of findings) {
      console.log(`\n[${item.severity.toUpperCase()}] ${item.id}: ${item.title}`);
      console.log(`Evidence: ${item.evidence}`);
      console.log(`Remediation: ${item.remediation}`);
    }
  }

  const workflow = new RemediationWorkflow(findings);
  workflow.on("remediation", event => {
    console.log(`Remediation event: ${JSON.stringify(event)}`);
  });

  const firstCritical = findings.find(item => item.severity === "critical");
  if (firstCritical) {
    workflow.recordAction(
      firstCritical.id,
      "accepted",
      "security-operator"
    );
    console.log(
      `Unresolved critical/high findings: ${workflow.unresolvedCriticalOrHigh().length}`
    );
  }
}

main();
