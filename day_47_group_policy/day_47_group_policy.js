"use strict";

/*
 * Event-driven Group Policy workflow simulator.
 * Runtime: Node.js 18 or later. No third-party packages required.
 *
 * The model distinguishes policy definitions, links, precedence, audit
 * decisions, and the final workstation configuration. It is a teaching
 * simulation, not an implementation of the Windows policy engine.
 */

const { EventEmitter } = require("node:events");
const assert = require("node:assert/strict");

const CATEGORY = Object.freeze({
  SECURITY: "security",
  PASSWORD: "password",
  WORKSTATION: "workstation",
});

const SCOPE_DEPTH = Object.freeze({
  site: 0,
  domain: 1,
  ou: 2,
});

class PolicyValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "PolicyValidationError";
  }
}

function validateSetting(name, value, category) {
  const booleanNames = new Set([
    "firewallEnabled",
    "usbStorageBlocked",
    "screenLockEnabled",
    "complexityEnabled",
    "accountLockoutEnabled",
    "localAdminInstallationBlocked",
    "interactiveLogonBannerEnabled",
  ]);

  const integerRanges = {
    minimumPasswordLength: [8, 128],
    passwordHistoryCount: [0, 50],
    maximumPasswordAgeDays: [0, 365],
    minimumPasswordAgeDays: [0, 365],
    lockoutThreshold: [0, 999],
    screenLockTimeoutMinutes: [1, 1440],
  };

  if (typeof name !== "string" || name.trim() === "") {
    throw new PolicyValidationError("Setting names must be non-empty.");
  }

  if (booleanNames.has(name) && typeof value !== "boolean") {
    throw new PolicyValidationError(`${name} must be Boolean.`);
  }

  if (Object.hasOwn(integerRanges, name)) {
    if (!Number.isSafeInteger(value)) {
      throw new PolicyValidationError(`${name} must be a safe integer.`);
    }

    const [minimum, maximum] = integerRanges[name];
    if (value < minimum || value > maximum) {
      throw new PolicyValidationError(
        `${name} must be between ${minimum} and ${maximum}.`,
      );
    }
  }

  const passwordNames = new Set([
    "minimumPasswordLength",
    "passwordHistoryCount",
    "maximumPasswordAgeDays",
    "minimumPasswordAgeDays",
    "complexityEnabled",
  ]);

  if (passwordNames.has(name) && category !== CATEGORY.PASSWORD) {
    throw new PolicyValidationError(
      `${name} must use the password category.`,
    );
  }

  if (
    ["firewallEnabled", "usbStorageBlocked", "screenLockEnabled",
      "screenLockTimeoutMinutes", "localAdminInstallationBlocked"].includes(name)
    && category !== CATEGORY.WORKSTATION
  ) {
    throw new PolicyValidationError(
      `${name} must use the workstation category.`,
    );
  }
}

class GroupPolicyObject {
  constructor(name, settings = {}, enabled = true) {
    if (!name || typeof name !== "string") {
      throw new PolicyValidationError("A GPO requires a name.");
    }

    this.name = name;
    this.enabled = Boolean(enabled);
    this.settings = new Map();

    for (const [settingName, definition] of Object.entries(settings)) {
      this.setSetting(settingName, definition.value, definition.category);
    }
  }

  setSetting(name, value, category) {
    validateSetting(name, value, category);

    // Freeze each setting record so a caller cannot silently mutate a value
    // without passing through validation.
    this.settings.set(name, Object.freeze({ name, value, category }));
  }
}

class PolicyRepository {
  constructor() {
    this.gpos = new Map();
    this.links = [];
  }

  addGpo(gpo) {
    if (this.gpos.has(gpo.name)) {
      throw new PolicyValidationError(`Duplicate GPO: ${gpo.name}`);
    }
    this.gpos.set(gpo.name, gpo);
  }

  linkGpo(link) {
    if (!this.gpos.has(link.gpoName)) {
      throw new PolicyValidationError(`Unknown GPO: ${link.gpoName}`);
    }

    if (!Object.hasOwn(SCOPE_DEPTH, link.scopeType)) {
      throw new PolicyValidationError("Unknown scope type.");
    }

    if (!Number.isInteger(link.linkOrder) || link.linkOrder < 1) {
      throw new PolicyValidationError("Link order must be a positive integer.");
    }

    this.links.push(Object.freeze({
      mode: "normal",
      enabled: true,
      ...link,
    }));
  }

  linksFor(machine) {
    const scopeKeys = new Set([
      `site:${machine.site}`,
      `domain:${machine.domain}`,
      ...machine.organizationalUnits.map((ou) => `ou:${ou}`),
    ]);

    return this.links
      .filter((link) =>
        link.enabled &&
        scopeKeys.has(`${link.scopeType}:${link.scopeName}`) &&
        this.gpos.get(link.gpoName).enabled
      )
      .sort((left, right) =>
        SCOPE_DEPTH[left.scopeType] - SCOPE_DEPTH[right.scopeType] ||
        left.linkOrder - right.linkOrder ||
        left.gpoName.localeCompare(right.gpoName)
      );
  }
}

class PolicyEvaluator extends EventEmitter {
  constructor(repository) {
    super();
    this.repository = repository;
  }

  evaluate(machine) {
    const links = this.repository.linksFor(machine);
    const values = new Map();
    const sources = new Map();
    const enforced = new Set();
    const appliedGpos = [];

    for (const link of links) {
      const gpo = this.repository.gpos.get(link.gpoName);
      appliedGpos.push(gpo.name);

      for (const [name, definition] of gpo.settings) {
        if (link.mode === "enforced") {
          values.set(name, definition.value);
          sources.set(name, gpo.name);
          enforced.add(name);
        } else if (!enforced.has(name)) {
          values.set(name, definition.value);
          sources.set(name, gpo.name);
        }
      }
    }

    const effectiveSettings = Object.fromEntries(values);
    const sourceBySetting = Object.fromEntries(sources);
    const warnings = [];

    if (effectiveSettings.screenLockEnabled === false) {
      warnings.push("Automatic screen lock is disabled.");
    }
    if (effectiveSettings.firewallEnabled === false) {
      warnings.push("The workstation firewall is disabled.");
    }
    if (
      effectiveSettings.maximumPasswordAgeDays > 0 &&
      effectiveSettings.minimumPasswordAgeDays >
        effectiveSettings.maximumPasswordAgeDays
    ) {
      warnings.push("Password age limits are inconsistent.");
    }

    const result = Object.freeze({
      hostname: machine.hostname,
      effectiveSettings,
      sourceBySetting,
      appliedGpos,
      warnings,
    });

    this.emit("evaluated", result);
    return result;
  }
}

function createEnvironment() {
  const repository = new PolicyRepository();

  repository.addGpo(new GroupPolicyObject("Domain-Security", {
    firewallEnabled: {
      value: true,
      category: CATEGORY.WORKSTATION,
    },
    minimumPasswordLength: {
      value: 14,
      category: CATEGORY.PASSWORD,
    },
    passwordHistoryCount: {
      value: 24,
      category: CATEGORY.PASSWORD,
    },
    complexityEnabled: {
      value: true,
      category: CATEGORY.PASSWORD,
    },
    maximumPasswordAgeDays: {
      value: 0,
      category: CATEGORY.PASSWORD,
    },
    minimumPasswordAgeDays: {
      value: 1,
      category: CATEGORY.PASSWORD,
    },
    interactiveLogonBannerEnabled: {
      value: true,
      category: CATEGORY.SECURITY,
    },
  }));

  repository.addGpo(new GroupPolicyObject("Engineering-Restrictions", {
    usbStorageBlocked: {
      value: true,
      category: CATEGORY.WORKSTATION,
    },
    screenLockEnabled: {
      value: true,
      category: CATEGORY.WORKSTATION,
    },
    screenLockTimeoutMinutes: {
      value: 10,
      category: CATEGORY.WORKSTATION,
    },
    localAdminInstallationBlocked: {
      value: true,
      category: CATEGORY.WORKSTATION,
    },
  }));

  repository.addGpo(new GroupPolicyObject("Legacy-Exception", {
    firewallEnabled: {
      value: false,
      category: CATEGORY.WORKSTATION,
    },
  }));

  repository.linkGpo({
    gpoName: "Domain-Security",
    scopeType: "domain",
    scopeName: "corp.example",
    linkOrder: 1,
    mode: "enforced",
  });

  repository.linkGpo({
    gpoName: "Engineering-Restrictions",
    scopeType: "ou",
    scopeName: "Engineering",
    linkOrder: 1,
  });

  repository.linkGpo({
    gpoName: "Legacy-Exception",
    scopeType: "ou",
    scopeName: "Engineering",
    linkOrder: 2,
  });

  const machine = {
    hostname: "ENG-WS-042",
    site: "North-Office",
    domain: "corp.example",
    organizationalUnits: ["Engineering"],
  };

  return { repository, machine };
}

function auditPasswordPolicy(settings) {
  const findings = [];

  if ((settings.minimumPasswordLength ?? 0) < 14) {
    findings.push("Password length is below the 14-character baseline.");
  }
  if ((settings.passwordHistoryCount ?? 0) < 12) {
    findings.push("Password history is shorter than required.");
  }
  if (settings.complexityEnabled !== true) {
    findings.push("Password complexity is not enabled.");
  }

  return findings;
}

function validatePasswordCandidate(candidate, settings) {
  if (typeof candidate !== "string") {
    throw new TypeError("Password candidate must be a string.");
  }

  const findings = [];
  if (candidate.length < settings.minimumPasswordLength) {
    findings.push("Insufficient length.");
  }
  if (settings.complexityEnabled) {
    if (!/[a-z]/.test(candidate)) findings.push("Missing lowercase.");
    if (!/[A-Z]/.test(candidate)) findings.push("Missing uppercase.");
    if (!/[0-9]/.test(candidate)) findings.push("Missing digit.");
    if (!/[^A-Za-z0-9]/.test(candidate)) {
      findings.push("Missing non-alphanumeric character.");
    }
  }

  // Do not log, persist, or transmit candidate passwords. This local check
  // cannot detect compromised passwords or enforce account-specific history.
  return { acceptedByLocalChecks: findings.length === 0, findings };
}

function main() {
  const { repository, machine } = createEnvironment();
  const evaluator = new PolicyEvaluator(repository);

  evaluator.on("evaluated", (result) => {
    console.log(`Policy evaluation completed for ${result.hostname}.`);
  });

  const result = evaluator.evaluate(machine);

  assert.equal(result.effectiveSettings.firewallEnabled, true);
  assert.equal(result.sourceBySetting.firewallEnabled, "Domain-Security");
  assert.equal(result.effectiveSettings.usbStorageBlocked, true);

  console.log(JSON.stringify(result, null, 2));
  console.log("Password policy findings:", auditPasswordPolicy(
    result.effectiveSettings,
  ));

  const candidate = validatePasswordCandidate(
    "Example-Only-Passphrase-2026",
    result.effectiveSettings,
  );
  console.log("Password candidate check:", candidate);

  // Disabled links do not participate in evaluation.
  repository.gpos.get("Engineering-Restrictions").enabled = false;
  const afterDisable = evaluator.evaluate(machine);
  assert.equal(
    Object.hasOwn(afterDisable.effectiveSettings, "usbStorageBlocked"),
    false,
  );

  assert.throws(
    () => validateSetting(
      "minimumPasswordLength",
      4,
      CATEGORY.PASSWORD,
    ),
    PolicyValidationError,
  );

  console.log("All assertions passed.");
}

main();
