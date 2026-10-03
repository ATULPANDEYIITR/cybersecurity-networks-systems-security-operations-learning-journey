#!/usr/bin/env node

/**
 * Linux permissions workflow simulator.
 *
 * This implementation emphasizes JavaScript-specific event-driven behavior:
 * permission requests become events, policy evaluation produces decisions,
 * and listeners can record or react to audit events.
 *
 * It models Linux concepts without changing the host filesystem.
 */

"use strict";

const EventEmitter = require("node:events");
const fs = require("node:fs");

const Permission = Object.freeze({
  READ: "r",
  WRITE: "w",
  EXECUTE: "x",
});

const PermissionBits = Object.freeze({
  r: 4,
  w: 2,
  x: 1,
});

function permissionsFromBits(bits) {
  return new Set(
    Object.entries(PermissionBits)
      .filter(([, value]) => (bits & value) !== 0)
      .map(([key]) => key)
  );
}

function bitsFromPermissions(permissions) {
  let bits = 0;
  for (const permission of permissions) {
    bits |= PermissionBits[permission] ?? 0;
  }
  return bits;
}

function permissionText(permissions) {
  return [...permissions].sort().join("");
}

function parseOctalMode(mode) {
  if (!/^[0-7]{3,4}$/.test(mode)) {
    throw new Error(`Invalid mode: ${mode}`);
  }
  const parsed = Number.parseInt(mode, 8);
  if (parsed > 0o7777) {
    throw new Error(`Mode exceeds 07777: ${mode}`);
  }
  return parsed;
}

function modeToString(mode, kind = "file") {
  const prefix = kind === "directory" ? "d" : "-";
  const classes = [6, 3, 0]
    .map((shift) => {
      const bits = (mode >> shift) & 0o7;
      return [
        bits & 4 ? "r" : "-",
        bits & 2 ? "w" : "-",
        bits & 1 ? "x" : "-",
      ].join("");
    })
    .join("");

  let result = prefix + classes;

  if (mode & 0o4000) {
    result =
      result.slice(0, 3) +
      (mode & 0o100 ? "s" : "S") +
      result.slice(4);
  }

  if (mode & 0o2000) {
    result =
      result.slice(0, 6) +
      (mode & 0o010 ? "s" : "S") +
      result.slice(7);
  }

  if (mode & 0o1000) {
    result = result.slice(0, -1) + (mode & 0o001 ? "t" : "T");
  }

  return result;
}

class Principal {
  constructor(username, uid, groups = [], root = false) {
    this.username = username;
    this.uid = uid;
    this.groups = new Set(groups);
    this.root = root;
  }
}

class AccessControlEntry {
  constructor() {
    this.users = new Map();
    this.groups = new Map();
    this.mask = new Set(["r", "w", "x"]);
  }

  setUser(username, permissions) {
    this.users.set(username, new Set(permissions));
  }

  setGroup(group, permissions) {
    this.groups.set(group, new Set(permissions));
  }

  setMask(permissions) {
    this.mask = new Set(permissions);
  }
}

class RepositoryFile {
  constructor({
    path,
    kind,
    owner,
    group,
    mode,
    parent = null,
    acl = null,
  }) {
    this.path = path;
    this.kind = kind;
    this.owner = owner;
    this.group = group;
    this.mode = mode;
    this.parent = parent;
    this.acl = acl;
  }

  get isDirectory() {
    return this.kind === "directory";
  }
}

class PermissionEngine extends EventEmitter {
  constructor() {
    super();

    this.users = new Map();
    this.objects = new Map();
    this.sudoRules = new Map();
    this.umask = 0o022;

    this.#createPrincipals();
    this.#createPolicy();
    this.#createObjects();
  }

  #createPrincipals() {
    this.addUser(new Principal("root", 0, ["root"], true));
    this.addUser(new Principal("alice", 1001, ["developers"]));
    this.addUser(new Principal("bob", 1002, ["developers"]));
    this.addUser(new Principal("carol", 1003, ["auditors"]));
    this.addUser(new Principal("dave", 1004, ["operations"]));
  }

  #createPolicy() {
    this.sudoRules.set("alice", new Set([
      "systemctl restart inventory.service",
      "journalctl -u inventory.service",
    ]));

    this.sudoRules.set("dave", new Set([
      "systemctl restart inventory.service",
      "chown",
    ]));
  }

  #createObjects() {
    this.addObject(new RepositoryFile({
      path: "/srv",
      kind: "directory",
      owner: "root",
      group: "root",
      mode: 0o755,
    }));

    this.addObject(new RepositoryFile({
      path: "/srv/inventory",
      kind: "directory",
      owner: "root",
      group: "operations",
      mode: 0o2775,
      parent: "/srv",
    }));

    this.addObject(new RepositoryFile({
      path: "/srv/inventory/stock.csv",
      kind: "file",
      owner: "alice",
      group: "developers",
      mode: 0o664,
      parent: "/srv/inventory",
    }));

    this.addObject(new RepositoryFile({
      path: "/srv/inventory/deploy.sh",
      kind: "file",
      owner: "root",
      group: "operations",
      mode: 0o750,
      parent: "/srv/inventory",
    }));

    const reportAcl = new AccessControlEntry();
    reportAcl.setUser("carol", ["r"]);
    reportAcl.setMask(["r"]);

    this.addObject(new RepositoryFile({
      path: "/srv/inventory/shared-report.txt",
      kind: "file",
      owner: "root",
      group: "operations",
      mode: 0o640,
      parent: "/srv/inventory",
      acl: reportAcl,
    }));

    this.addObject(new RepositoryFile({
      path: "/srv/inventory/drop",
      kind: "directory",
      owner: "root",
      group: "operations",
      mode: 0o3770,
      parent: "/srv/inventory",
    }));
  }

  addUser(principal) {
    this.users.set(principal.username, principal);
  }

  addObject(object) {
    if (!this.users.has(object.owner)) {
      throw new Error(`Unknown owner: ${object.owner}`);
    }
    this.objects.set(object.path, object);
  }

  object(path) {
    const result = this.objects.get(path);
    if (!result) {
      throw new Error(`No such simulated object: ${path}`);
    }
    return result;
  }

  user(username) {
    const result = this.users.get(username);
    if (!result) {
      throw new Error(`Unknown user: ${username}`);
    }
    return result;
  }

  #aclPermissions(object, principal) {
    if (!object.acl) {
      return null;
    }

    if (object.acl.users.has(principal.username)) {
      return {
        permissions: new Set(
          [...object.acl.users.get(principal.username)]
            .filter((permission) => object.acl.mask.has(permission))
        ),
        source: `named ACL user:${principal.username}`,
      };
    }

    for (const group of principal.groups) {
      if (object.acl.groups.has(group)) {
        return {
          permissions: new Set(
            [...object.acl.groups.get(group)]
              .filter((permission) => object.acl.mask.has(permission))
          ),
          source: `named ACL group:${group}`,
        };
      }
    }

    return null;
  }

  decide(username, path, requested) {
    const principal = this.user(username);
    const object = this.object(path);

    if (principal.root) {
      return {
        allowed: true,
        source: "root",
        available: new Set(["r", "w", "x"]),
        reason: "root bypasses ordinary discretionary access checks",
      };
    }

    let source;
    let available;
    let reason;

    if (principal.username === object.owner) {
      source = "owner";
      available = permissionsFromBits((object.mode >> 6) & 7);
      reason = "owner mode bits";
    } else {
      const acl = this.#aclPermissions(object, principal);

      if (acl) {
        source = "ACL";
        available = acl.permissions;
        reason = acl.source;
      } else if (principal.groups.has(object.group)) {
        source = "group";
        available = permissionsFromBits((object.mode >> 3) & 7);

        if (object.acl) {
          available = new Set(
            [...available].filter((permission) =>
              object.acl.mask.has(permission)
            )
          );
          reason = "owning group bits limited by ACL mask";
        } else {
          reason = "owning group mode bits";
        }
      } else {
        source = "other";
        available = permissionsFromBits(object.mode & 7);
        reason = "other mode bits";
      }
    }

    const missing = [...requested].filter(
      (permission) => !available.has(permission)
    );

    return {
      allowed: missing.length === 0,
      source,
      available,
      reason: missing.length
        ? `${reason}; missing ${missing.join("")}`
        : reason,
    };
  }

  traverse(username, path) {
    const components = path.split("/").filter(Boolean);
    let current = "";

    for (let index = 0; index < components.length - 1; index += 1) {
      current += `/${components[index]}`;

      const decision = this.decide(username, current, new Set(["x"]));
      if (!decision.allowed) {
        throw new Error(
          `Traversal denied at ${current}: ${decision.reason}`
        );
      }
    }
  }

  read(username, path) {
    this.traverse(username, path);

    const decision = this.decide(username, path, new Set(["r"]));
    this.emit("access", {
      operation: "read",
      username,
      path,
      decision,
    });

    if (!decision.allowed) {
      throw new Error(`Read denied: ${decision.reason}`);
    }

    return `simulated contents of ${path}`;
  }

  write(username, path) {
    this.traverse(username, path);

    const decision = this.decide(username, path, new Set(["w"]));
    this.emit("access", {
      operation: "write",
      username,
      path,
      decision,
    });

    if (!decision.allowed) {
      throw new Error(`Write denied: ${decision.reason}`);
    }

    return true;
  }

  createFile(username, directory, filename) {
    const parent = this.object(directory);

    if (!parent.isDirectory) {
      throw new Error(`${directory} is not a directory`);
    }

    const decision = this.decide(
      username,
      directory,
      new Set(["w", "x"])
    );

    if (!decision.allowed) {
      throw new Error(`Creation denied: ${decision.reason}`);
    }

    const path = `${directory.replace(/\/$/, "")}/${filename}`;

    if (this.objects.has(path)) {
      throw new Error(`${path} already exists`);
    }

    const principal = this.user(username);

    const group = parent.mode & 0o2000
      ? parent.group
      : [...principal.groups][0] ?? "users";

    const mode = 0o664 & ~this.umask;

    this.addObject(new RepositoryFile({
      path,
      kind: "file",
      owner: username,
      group,
      mode,
      parent: directory,
    }));

    this.emit("filesystem", {
      operation: "create",
      username,
      path,
      mode,
      group,
    });

    return path;
  }

  chmod(username, path, mode) {
    const object = this.object(path);
    const principal = this.user(username);

    if (!principal.root && principal.username !== object.owner) {
      throw new Error(
        "chmod denied: actor must own the object or have privilege"
      );
    }

    if (mode < 0 || mode > 0o7777) {
      throw new Error("chmod mode must be between 0000 and 07777");
    }

    object.mode = mode;

    this.emit("policy", {
      operation: "chmod",
      username,
      path,
      mode,
    });
  }

  chown(username, path, owner, group) {
    const principal = this.user(username);
    const object = this.object(path);

    if (!principal.root) {
      throw new Error(
        "chown denied: ownership changes require privileged authority"
      );
    }

    if (!this.users.has(owner)) {
      throw new Error(`Unknown owner: ${owner}`);
    }

    object.owner = owner;
    object.group = group;

    this.emit("policy", {
      operation: "chown",
      username,
      path,
      owner,
      group,
    });
  }

  setAclUser(username, path, targetUser, permissions) {
    const actor = this.user(username);
    const object = this.object(path);

    if (!actor.root && actor.username !== object.owner) {
      throw new Error("setfacl denied: insufficient authority");
    }

    if (!this.users.has(targetUser)) {
      throw new Error(`Unknown ACL user: ${targetUser}`);
    }

    object.acl ??= new AccessControlEntry();
    object.acl.setUser(targetUser, permissions);

    this.emit("policy", {
      operation: "setfacl",
      username,
      path,
      targetUser,
      permissions: permissionText(permissions),
    });
  }

  setAclMask(username, path, permissions) {
    const actor = this.user(username);
    const object = this.object(path);

    if (!actor.root && actor.username !== object.owner) {
      throw new Error("setfacl mask denied: insufficient authority");
    }

    object.acl ??= new AccessControlEntry();
    object.acl.setMask(permissions);
  }

  sudo(username, command) {
    const principal = this.user(username);

    if (principal.root) {
      return true;
    }

    const allowed = this.sudoRules.get(username)?.has(command) ?? false;

    this.emit("sudo", {
      username,
      command,
      allowed,
    });

    if (!allowed) {
      throw new Error(`sudo policy denied: ${username} -> ${command}`);
    }

    return true;
  }

  runSudo(username, command) {
    this.sudo(username, command);
    return {
      command,
      requestedBy: username,
      effectiveUser: "root",
    };
  }

  describe(path) {
    const object = this.object(path);
    return `${modeToString(object.mode, object.kind)} ${object.mode.toString(8).padStart(4, "0")} ${object.owner}:${object.group} ${object.path}`;
  }
}

function installAuditListeners(engine) {
  engine.on("access", (event) => {
    const result = event.decision.allowed ? "ALLOW" : "DENY";
    console.log(
      `[audit] ${result} ${event.operation} ${event.username} ${event.path} ` +
      `source=${event.decision.source}`
    );
  });

  engine.on("sudo", (event) => {
    console.log(
      `[sudo-audit] ${event.username} command="${event.command}" ` +
      `result=${event.allowed ? "ALLOW" : "DENY"}`
    );
  });

  engine.on("policy", (event) => {
    console.log(
      `[policy] ${event.operation} actor=${event.username} path=${event.path}`
    );
  });
}

function showAccess(engine, username, path, permissions) {
  const decision = engine.decide(
    username,
    path,
    new Set(permissions.split(""))
  );

  console.log(
    `${username.padEnd(6)} ${permissions.padEnd(3)} ` +
    `${path.padEnd(38)} ${decision.allowed ? "ALLOW" : "DENY "} ` +
    `[${decision.source}] ${decision.reason}`
  );
}

function demonstrateModeAndOwnership(engine) {
  console.log("\n=== mode bits and ownership ===");

  const path = "/srv/inventory/stock.csv";
  console.log(engine.describe(path));

  try {
    engine.chmod("bob", path, 0o600);
  } catch (error) {
    console.log(`Expected chmod boundary: ${error.message}`);
  }

  engine.chmod("alice", path, 0o660);
  console.log(`After owner chmod: ${engine.describe(path)}`);

  try {
    engine.chown("alice", path, "bob", "developers");
  } catch (error) {
    console.log(`Expected chown boundary: ${error.message}`);
  }

  engine.chown("root", path, "bob", "developers");
  console.log(`After privileged chown: ${engine.describe(path)}`);

  engine.chown("root", path, "alice", "developers");
  engine.chmod("alice", path, 0o664);
}

function demonstrateAcl(engine) {
  console.log("\n=== ACL-specific access ===");

  const path = "/srv/inventory/shared-report.txt";

  showAccess(engine, "carol", path, "r");
  showAccess(engine, "carol", path, "w");

  engine.setAclUser("root", path, "carol", ["r", "w"]);
  engine.setAclMask("root", path, ["r", "w"]);

  showAccess(engine, "carol", path, "rw");

  // Reducing the ACL mask affects named entries without changing the named
  // user's stored permissions.
  engine.setAclMask("root", path, ["r"]);
  showAccess(engine, "carol", path, "w");
}

function demonstrateTraversal(engine) {
  console.log("\n=== directory search permission ===");

  const directory = engine.object("/srv/inventory");
  const original = directory.mode;

  directory.mode = 0o770;

  try {
    engine.read("carol", "/srv/inventory/shared-report.txt");
  } catch (error) {
    console.log(`Expected traversal boundary: ${error.message}`);
  }

  directory.mode = original;
}

function demonstrateSudo(engine) {
  console.log("\n=== sudo as a policy boundary ===");

  console.log(
    engine.runSudo(
      "alice",
      "systemctl restart inventory.service"
    )
  );

  try {
    engine.runSudo("alice", "chown");
  } catch (error) {
    console.log(`Expected sudo denial: ${error.message}`);
  }

  try {
    engine.runSudo("bob", "systemctl restart inventory.service");
  } catch (error) {
    console.log(`Expected sudo denial: ${error.message}`);
  }
}

function demonstrateUmaskAndSetgid(engine) {
  console.log("\n=== umask plus setgid directory ===");

  engine.umask = 0o027;

  const path = engine.createFile(
    "alice",
    "/srv/inventory",
    "generated-report.csv"
  );

  console.log(
    `${path} -> mode=${engine.object(path).mode.toString(8)} ` +
    `group=${engine.object(path).group}`
  );

  console.log(
    "The directory's setgid bit keeps newly created files in the " +
    "directory's collaboration group in this model."
  );
}

function demonstrateHostObservation() {
  console.log("\n=== host observation ===");

  const file = process.argv[1];
  const metadata = fs.statSync(file);

  console.log(`Running file: ${file}`);
  console.log(`Host UID: ${metadata.uid}`);
  console.log(`Host GID: ${metadata.gid}`);
  console.log(`Host mode: ${(metadata.mode & 0o7777).toString(8)}`);

  // The simulator remains separate from the host so chmod/chown examples
  // cannot accidentally alter the user's real files.
}

function run() {
  const engine = new PermissionEngine();
  installAuditListeners(engine);

  console.log("Linux Permission Workflow Simulator");
  console.log("===================================");

  demonstrateModeAndOwnership(engine);
  demonstrateAcl(engine);
  demonstrateTraversal(engine);
  demonstrateSudo(engine);
  demonstrateUmaskAndSetgid(engine);

  console.log("\n=== access matrix ===");
  showAccess(engine, "alice", "/srv/inventory/stock.csv", "rw");
  showAccess(engine, "bob", "/srv/inventory/stock.csv", "rw");
  showAccess(engine, "carol", "/srv/inventory/shared-report.txt", "r");
  showAccess(engine, "dave", "/srv/inventory/deploy.sh", "x");

  demonstrateHostObservation();
}

run();
