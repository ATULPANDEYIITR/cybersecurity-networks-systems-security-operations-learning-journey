"use strict";

/*
 * Windows Registry workflow model.
 * Runs with Node.js without dependencies. The simulator is deliberately
 * separate from the real Windows registry, which this file never modifies.
 */

const TYPES = new Set([
  "REG_SZ",
  "REG_EXPAND_SZ",
  "REG_DWORD",
  "REG_QWORD",
  "REG_BINARY",
  "REG_MULTI_SZ",
]);

class RegistryError extends Error {}
class RegistryValidationError extends RegistryError {}
class RegistryAccessError extends RegistryError {}

function normalizePath(path) {
  if (typeof path !== "string" || !path.trim()) {
    throw new RegistryValidationError("A registry path is required.");
  }

  const parts = path.replaceAll("/", "\\").replace(/^\\+|\\+$/g, "").split("\\");
  const hives = new Set([
    "HKCU", "HKLM", "HKCR", "HKU", "HKCC",
    "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE",
    "HKEY_CLASSES_ROOT", "HKEY_USERS", "HKEY_CURRENT_CONFIG",
  ]);

  if (!hives.has(parts[0].toUpperCase())) {
    throw new RegistryValidationError(`Unsupported hive: ${parts[0]}`);
  }

  if (parts.some((part) => !part || part === "." || part === ".." || part.includes("\0"))) {
    throw new RegistryValidationError("Invalid path component.");
  }

  return parts.join("\\");
}

function validateValue(type, value) {
  if (!TYPES.has(type)) {
    throw new RegistryValidationError(`Unsupported registry type: ${type}`);
  }

  if (type === "REG_SZ" || type === "REG_EXPAND_SZ") {
    if (typeof value !== "string" || value.includes("\0")) {
      throw new RegistryValidationError(`${type} requires a valid string.`);
    }
  } else if (type === "REG_DWORD") {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new RegistryValidationError("REG_DWORD must be an unsigned 32-bit integer.");
    }
  } else if (type === "REG_QWORD") {
    if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) {
      throw new RegistryValidationError("REG_QWORD requires a valid unsigned BigInt.");
    }
  } else if (type === "REG_BINARY" && !Buffer.isBuffer(value)) {
    throw new RegistryValidationError("REG_BINARY requires a Buffer.");
  } else if (
    type === "REG_MULTI_SZ" &&
    (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.includes("\0")))
  ) {
    throw new RegistryValidationError("REG_MULTI_SZ requires an array of valid strings.");
  }
}

class RegistryKey {
  constructor(path) {
    this.path = path;
    this.values = new Map();
    this.children = new Map();
  }

  child(name) {
    const normalized = name.toLocaleLowerCase("en-US");
    return this.children.get(normalized);
  }

  addChild(name) {
    const normalized = name.toLocaleLowerCase("en-US");
    if (!this.children.has(normalized)) {
      this.children.set(normalized, new RegistryKey(`${this.path}\\${name}`));
    }
    return this.children.get(normalized);
  }
}

class RegistryModel {
  constructor() {
    this.roots = new Map();
    for (const hive of ["HKCU", "HKLM", "HKCR", "HKU", "HKCC"]) {
      this.roots.set(hive, new RegistryKey(hive));
    }
    this.permissions = new Map();
    this.events = [];
  }

  resolve(path, create = false) {
    const parts = normalizePath(path).split("\\");
    const aliases = {
      HKEY_CURRENT_USER: "HKCU",
      HKEY_LOCAL_MACHINE: "HKLM",
      HKEY_CLASSES_ROOT: "HKCR",
      HKEY_USERS: "HKU",
      HKEY_CURRENT_CONFIG: "HKCC",
    };
    const hive = aliases[parts[0].toUpperCase()] || parts[0].toUpperCase();
    let current = this.roots.get(hive);

    for (const part of parts.slice(1)) {
      let next = current.child(part);
      if (!next && create) next = current.addChild(part);
      if (!next) throw new RegistryError(`Key not found: ${path}`);
      current = next;
    }

    return current;
  }

  setPermissions(path, operations) {
    this.permissions.set(normalizePath(path).toLocaleLowerCase("en-US"), new Set(operations));
  }

  authorize(path, operation) {
    const normalized = normalizePath(path).toLocaleLowerCase("en-US");
    const parts = normalized.split("\\");
    for (let index = 1; index <= parts.length; index += 1) {
      const ancestor = parts.slice(0, index).join("\\");
      const allowed = this.permissions.get(ancestor);
      if (allowed && !allowed.has(operation)) {
        this.events.push({ path, operation, result: "DENIED" });
        throw new RegistryAccessError(`${operation} denied: ${path}`);
      }
    }
    this.events.push({ path, operation, result: "ALLOWED" });
  }

  setValue(path, name, type, value) {
    this.authorize(path, "write");
    if (typeof name !== "string" || name.includes("\0")) {
      throw new RegistryValidationError("Invalid value name.");
    }
    validateValue(type, value);

    const key = this.resolve(path, true);
    key.values.set(name.toLocaleLowerCase("en-US"), {
      name,
      type,
      value,
    });
  }

  getValue(path, name = "") {
    this.authorize(path, "read");
    const entry = this.resolve(path).values.get(name.toLocaleLowerCase("en-US"));
    if (!entry) throw new RegistryError(`Value not found: ${path}\\${name}`);
    return entry;
  }

  listSubkeys(path) {
    this.authorize(path, "enumerate");
    return [...this.resolve(path).children.values()]
      .map((child) => child.path.split("\\").at(-1))
      .sort((a, b) => a.localeCompare(b));
  }

  deleteValue(path, name) {
    this.authorize(path, "delete");
    const values = this.resolve(path).values;
    const deleted = values.delete(name.toLocaleLowerCase("en-US"));
    if (!deleted) throw new RegistryError(`Value not found: ${path}\\${name}`);
  }
}

/*
 * Event-driven lifecycle separates proposed changes from review decisions.
 * Approval is a review outcome; branch policy determines merge eligibility.
 */
class PullRequest {
  constructor({ id, source, target, author, draft = false }) {
    if (!Number.isInteger(id) || id <= 0 || !source || !target || source === target) {
      throw new RegistryValidationError("Invalid pull request metadata.");
    }
    this.id = id;
    this.source = source;
    this.target = target;
    this.author = author;
    this.state = draft ? "DRAFT" : "OPEN";
    this.commits = [];
    this.reviews = new Map();
    this.checks = new Map();
    this.discussions = new Map();
    this.events = [];
    this.baseRevision = 1;
  }

  emit(type, detail = {}) {
    this.events.push({ type, at: new Date().toISOString(), ...detail });
  }

  addCommit(sha, baseRevision) {
    if (this.state !== "OPEN" && this.state !== "DRAFT") {
      throw new RegistryError("Commits cannot be added to a closed request.");
    }
    if (!/^[a-f0-9]{7,40}$/i.test(sha)) {
      throw new RegistryValidationError("Commit must have a valid hexadecimal identifier.");
    }
    this.commits.push(sha);
    if (baseRevision !== this.baseRevision) {
      this.reviews.clear();
      this.emit("STALE_REVIEWS_CLEARED", { reason: "Base branch changed." });
    }
    this.emit("COMMIT_ADDED", { sha });
  }

  markReady() {
    if (this.state !== "DRAFT") throw new RegistryError("Only drafts can become ready.");
    this.state = "OPEN";
    this.emit("READY_FOR_REVIEW");
  }

  submitReview(reviewer, state, commitSha) {
    if (this.state !== "OPEN") throw new RegistryError("Request is not open for review.");
    if (reviewer === this.author) throw new RegistryError("Authors cannot approve their own changes.");
    if (!["APPROVED", "CHANGES_REQUESTED", "COMMENTED"].includes(state)) {
      throw new RegistryValidationError("Unknown review state.");
    }
    this.reviews.set(reviewer, { state, commitSha });
    this.emit("REVIEW_SUBMITTED", { reviewer, state });
  }

  setCheck(name, state) {
    if (!["SUCCESS", "FAILURE", "PENDING"].includes(state)) {
      throw new RegistryValidationError("Invalid check state.");
    }
    this.checks.set(name, state);
    this.emit("CHECK_UPDATED", { name, state });
  }

  addDiscussion(id, resolved = false) {
    this.discussions.set(id, { resolved });
    this.emit("DISCUSSION_UPDATED", { id, resolved });
  }

  syncBase(revision) {
    if (!Number.isInteger(revision) || revision <= this.baseRevision) {
      throw new RegistryValidationError("Base revision must advance.");
    }
    this.baseRevision = revision;
    this.reviews.clear();
    this.emit("BASE_SYNCHRONIZED", { revision, approvalsInvalidated: true });
  }

  merge(policy) {
    const approved = [...this.reviews.entries()].filter(
      ([, review]) => review.state === "APPROVED",
    ).length;
    const blockers = [];

    if (this.state !== "OPEN") blockers.push("Request must be open.");
    if (this.commits.length === 0) blockers.push("No commits to merge.");
    if (approved < policy.requiredApprovals) blockers.push("Insufficient approvals.");
    if (policy.requiredChecks.some((check) => this.checks.get(check) !== "SUCCESS")) {
      blockers.push("Required checks have not all passed.");
    }
    if (policy.requireResolvedDiscussions &&
        [...this.discussions.values()].some((discussion) => !discussion.resolved)) {
      blockers.push("Unresolved review discussions remain.");
    }
    if (policy.requireLinearHistory && policy.mergeMethod !== "REBASE") {
      blockers.push("Policy requires a linear-history merge method.");
    }

    if (blockers.length) return { merged: false, blockers };

    this.state = "MERGED";
    this.emit("MERGED", { method: policy.mergeMethod });
    return { merged: true, blockers: [] };
  }

  close() {
    if (this.state !== "OPEN" && this.state !== "DRAFT") {
      throw new RegistryError("Only open or draft requests can be closed.");
    }
    this.state = "CLOSED";
    this.emit("CLOSED");
  }

  reopen() {
    if (this.state !== "CLOSED") throw new RegistryError("Only closed requests can reopen.");
    this.state = "OPEN";
    this.emit("REOPENED");
  }
}

function main() {
  const registry = new RegistryModel();
  const path = "HKCU\\Software\\ExampleCorp\\ReleaseAgent";
  registry.setValue(path, "Channel", "REG_SZ", "stable");
  registry.setValue(path, "MaxRetries", "REG_DWORD", 4);
  registry.setValue(path, "InstallMarker", "REG_BINARY", Buffer.from([0x10, 0x20]));

  console.log("Typed configuration:", {
    channel: registry.getValue(path, "channel").value,
    maxRetries: registry.getValue(path, "MAXRETRIES").value,
    installMarker: registry.getValue(path, "InstallMarker").value.toString("hex"),
  });

  const protectedPath = `${path}\\Security`;
  registry.setValue(protectedPath, "PolicyRevision", "REG_DWORD", 2);
  registry.setPermissions(protectedPath, ["read", "enumerate"]);
  try {
    registry.setValue(protectedPath, "PolicyRevision", "REG_DWORD", 3);
  } catch (error) {
    console.log("Registry access control:", error.message);
  }

  const request = new PullRequest({
    id: 42,
    source: "feature/secure-configuration",
    target: "main",
    author: "developer-alex",
    draft: true,
  });

  request.markReady();
  request.addCommit("a81f2c9", 1);
  request.addDiscussion("inline-comment-17", false);
  request.submitReview("reviewer-mira", "APPROVED", "a81f2c9");
  request.setCheck("unit-tests", "SUCCESS");
  request.setCheck("security-scan", "SUCCESS");

  const policy = {
    requiredApprovals: 1,
    requiredChecks: ["unit-tests", "security-scan"],
    requireResolvedDiscussions: true,
    requireLinearHistory: true,
    mergeMethod: "REBASE",
  };

  console.log("Initial merge decision:", request.merge(policy));
  request.addDiscussion("inline-comment-17", true);
  console.log("Final merge decision:", request.merge(policy));
  console.log("Request lifecycle events:", request.events.map((event) => event.type));
}

if (require.main === module) {
  main();
}

module.exports = {
  RegistryModel,
  RegistryError,
  RegistryValidationError,
  RegistryAccessError,
  PullRequest,
  normalizePath,
  validateValue,
};
