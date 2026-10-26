"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const EventEmitter = require("node:events");

const PatchStatus = Object.freeze({
  PLANNED: "planned",
  DEPLOYING: "deploying",
  VALIDATING: "validating",
  COMPLETED: "completed",
  FAILED: "failed",
  ROLLED_BACK: "rolled_back"
});

const Severity = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
});

const Environment = Object.freeze({
  DEVELOPMENT: "development",
  STAGING: "staging",
  PRODUCTION: "production"
});

class PatchError extends Error {}
class ValidationError extends PatchError {}
class DeploymentError extends PatchError {}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function assertVersion(version, field) {
  if (!/^\d+(?:\.\d+){1,3}$/.test(version)) {
    throw new ValidationError(`Invalid ${field}: ${version}`);
  }
}

class Patch {
  constructor({
    id,
    title,
    component,
    versionBefore,
    versionAfter,
    severity,
    releaseDate,
    requiresReboot,
    checksum
  }) {
    this.id = id;
    this.title = title;
    this.component = component;
    this.versionBefore = versionBefore;
    this.versionAfter = versionAfter;
    this.severity = severity;
    this.releaseDate = new Date(releaseDate);
    this.requiresReboot = requiresReboot;
    this.checksum = checksum;
    this.validate();
  }

  validate() {
    if (!/^P-\d{4,}$/.test(this.id)) {
      throw new ValidationError(`Invalid patch ID: ${this.id}`);
    }
    if (!this.title?.trim() || !this.component?.trim()) {
      throw new ValidationError("Patch title and component are required.");
    }
    assertVersion(this.versionBefore, "pre-patch version");
    assertVersion(this.versionAfter, "post-patch version");
    if (this.versionBefore === this.versionAfter) {
      throw new ValidationError("Patch must change the component version.");
    }
    if (!Object.values(Severity).includes(this.severity)) {
      throw new ValidationError(`Unsupported severity: ${this.severity}`);
    }
    if (!Number.isNaN(this.releaseDate.getTime()) === false) {
      throw new ValidationError("Invalid release date.");
    }
    if (!/^[a-f0-9]{64}$/.test(this.checksum)) {
      throw new ValidationError("Checksum must be SHA-256.");
    }
  }
}

class Server {
  constructor(id, hostname, environment, components) {
    if (!id || !hostname) {
      throw new ValidationError("Server ID and hostname are required.");
    }
    if (!Object.values(Environment).includes(environment)) {
      throw new ValidationError(`Invalid environment: ${environment}`);
    }
    this.id = id;
    this.hostname = hostname;
    this.environment = environment;
    this.components = new Map(Object.entries(components));
    this.online = true;
    this.rebootRequired = false;
    this.lastPatched = null;
  }
}

class PatchDeployment {
  constructor(patch, server) {
    this.patch = patch;
    this.server = server;
    this.status = PatchStatus.PLANNED;
    this.startedAt = null;
    this.completedAt = null;
    this.validationMessage = "";
  }

  transition(next) {
    const allowed = {
      [PatchStatus.PLANNED]: new Set([PatchStatus.DEPLOYING, PatchStatus.FAILED]),
      [PatchStatus.DEPLOYING]: new Set([PatchStatus.VALIDATING, PatchStatus.FAILED]),
      [PatchStatus.VALIDATING]: new Set([
        PatchStatus.COMPLETED,
        PatchStatus.FAILED,
        PatchStatus.ROLLED_BACK
      ]),
      [PatchStatus.FAILED]: new Set([PatchStatus.ROLLED_BACK]),
      [PatchStatus.COMPLETED]: new Set(),
      [PatchStatus.ROLLED_BACK]: new Set()
    };

    if (!allowed[this.status].has(next)) {
      throw new DeploymentError(
        `Invalid state transition ${this.status} -> ${next}`
      );
    }
    this.status = next;
  }
}

class PatchEventBus extends EventEmitter {}

class PatchManager {
  constructor() {
    this.patches = new Map();
    this.servers = new Map();
    this.deployments = [];
    this.events = new PatchEventBus();
  }

  addPatch(patch) {
    if (this.patches.has(patch.id)) {
      throw new ValidationError(`Patch already exists: ${patch.id}`);
    }
    this.patches.set(patch.id, patch);
  }

  addServer(server) {
    if (this.servers.has(server.id)) {
      throw new ValidationError(`Server already exists: ${server.id}`);
    }
    this.servers.set(server.id, server);
  }

  createWindow(start, end, environments) {
    if (start >= end) {
      throw new ValidationError("Patch window must have a positive duration.");
    }
    return {
      start,
      end,
      environments: new Set(environments),
      accepts(environment, now) {
        return (
          this.environments.has(environment) &&
          now >= this.start &&
          now <= this.end
        );
      }
    };
  }

  plan(patchId, serverId, window, now = new Date()) {
    const patch = this.patches.get(patchId);
    const server = this.servers.get(serverId);

    if (!patch) throw new ValidationError(`Unknown patch: ${patchId}`);
    if (!server) throw new ValidationError(`Unknown server: ${serverId}`);
    if (!server.online) {
      throw new DeploymentError(`${server.hostname} is offline.`);
    }
    if (!window.accepts(server.environment, now)) {
      throw new DeploymentError("Server is outside the approved patch window.");
    }

    const current = server.components.get(patch.component);
    if (current !== patch.versionBefore) {
      throw new ValidationError(
        `Expected ${patch.versionBefore}, found ${current ?? "missing"}.`
      );
    }

    const deployment = new PatchDeployment(patch, server);
    this.deployments.push(deployment);
    this.events.emit("planned", deployment);
    return deployment;
  }

  async deploy(deployment, observedChecksum, validationProbe) {
    const { patch, server } = deployment;

    if (observedChecksum !== patch.checksum) {
      deployment.transition(PatchStatus.FAILED);
      this.events.emit("failed", deployment);
      throw new DeploymentError("Patch checksum verification failed.");
    }

    deployment.transition(PatchStatus.DEPLOYING);
    deployment.startedAt = new Date();
    this.events.emit("deploying", deployment);

    try {
      // Real systems should replace this mutation with an atomic package
      // installation followed by service and health checks.
      server.components.set(patch.component, patch.versionAfter);

      if (patch.requiresReboot) {
        server.rebootRequired = true;
      }

      deployment.transition(PatchStatus.VALIDATING);
      this.events.emit("validating", deployment);

      const valid = await validationProbe(server);
      if (!valid) {
        deployment.validationMessage = "Post-patch validation failed.";
        deployment.transition(PatchStatus.FAILED);
        await this.rollback(deployment);
        return;
      }

      server.rebootRequired = false;
      server.lastPatched = new Date();
      deployment.validationMessage = "Validation passed.";
      deployment.transition(PatchStatus.COMPLETED);
      deployment.completedAt = new Date();
      this.events.emit("completed", deployment);
    } catch (error) {
      if (
        deployment.status !== PatchStatus.FAILED &&
        deployment.status !== PatchStatus.ROLLED_BACK
      ) {
        deployment.transition(PatchStatus.FAILED);
      }
      this.events.emit("failed", deployment);
      throw new DeploymentError(error.message);
    }
  }

  async rollback(deployment) {
    const { patch, server } = deployment;
    server.components.set(patch.component, patch.versionBefore);
    server.rebootRequired = false;

    if (deployment.status === PatchStatus.FAILED) {
      deployment.transition(PatchStatus.ROLLED_BACK);
    }

    deployment.validationMessage += " Rollback completed.";
    this.events.emit("rolledBack", deployment);
  }

  emergencyCandidates() {
    return [...this.patches.values()]
      .filter(
        p => p.severity === Severity.CRITICAL || p.severity === Severity.HIGH
      )
      .sort((a, b) => {
        const severityRank = {
          [Severity.CRITICAL]: 0,
          [Severity.HIGH]: 1,
          [Severity.MEDIUM]: 2,
          [Severity.LOW]: 3
        };
        return (
          severityRank[a.severity] - severityRank[b.severity] ||
          a.releaseDate - b.releaseDate
        );
      });
  }

  overdueServers(maxAgeDays = 30) {
    const cutoff = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
    return [...this.servers.values()].filter(
      server => !server.lastPatched || server.lastPatched.getTime() < cutoff
    );
  }

  async saveReport(file) {
    const report = {
      patches: [...this.patches.values()].map(p => ({
        id: p.id,
        title: p.title,
        component: p.component,
        versionBefore: p.versionBefore,
        versionAfter: p.versionAfter,
        severity: p.severity,
        requiresReboot: p.requiresReboot
      })),
      servers: [...this.servers.values()].map(s => ({
        id: s.id,
        hostname: s.hostname,
        environment: s.environment,
        components: Object.fromEntries(s.components),
        lastPatched: s.lastPatched?.toISOString() ?? null
      })),
      deployments: this.deployments.map(d => ({
        patchId: d.patch.id,
        serverId: d.server.id,
        status: d.status,
        validationMessage: d.validationMessage
      }))
    };

    await fs.writeFile(file, JSON.stringify(report, null, 2), "utf8");
  }
}

async function main() {
  const manager = new PatchManager();

  for (const event of ["planned", "deploying", "validating", "completed", "failed", "rolledBack"]) {
    manager.events.on(event, deployment => {
      console.log(
        `[event] ${event}: ${deployment.patch.id} -> ${deployment.server.hostname}`
      );
    });
  }

  const patch = new Patch({
    id: "P-2001",
    title: "OpenSSL security update",
    component: "openssl",
    versionBefore: "3.0.12",
    versionAfter: "3.0.17",
    severity: Severity.CRITICAL,
    releaseDate: new Date(),
    requiresReboot: false,
    checksum: sha256("openssl-3.0.17-security")
  });

  manager.addPatch(patch);
  manager.addServer(
    new Server(
      "srv-101",
      "payments-prod-01",
      Environment.PRODUCTION,
      {
        openssl: "3.0.12",
        "linux-kernel": "6.1.70"
      }
    )
  );

  const now = new Date();
  const window = manager.createWindow(
    new Date(now.getTime() - 5 * 60 * 1000),
    new Date(now.getTime() + 60 * 60 * 1000),
    [Environment.PRODUCTION]
  );

  const deployment = manager.plan("P-2001", "srv-101", window);

  await manager.deploy(
    deployment,
    patch.checksum,
    async server => {
      await new Promise(resolve => setTimeout(resolve, 20));
      return (
        server.online &&
        server.components.get("openssl") === "3.0.17" &&
        !server.rebootRequired
      );
    }
  );

  if (deployment.status !== PatchStatus.COMPLETED) {
    throw new DeploymentError("Demo deployment did not complete.");
  }

  console.log("Emergency candidates:", manager.emergencyCandidates().map(p => p.id));
  console.log("Overdue servers:", manager.overdueServers().map(s => s.hostname));

  await manager.saveReport("patch-management-report.json");
  console.log("Report written to patch-management-report.json");

  try {
    const bad = manager.plan("P-2001", "srv-101", window);
    await manager.deploy(bad, "bad-checksum", async () => true);
  } catch (error) {
    console.log(`Expected failure: ${error.message}`);
  }
}

main().catch(error => {
  console.error(`Fatal error: ${error.message}`);
  process.exitCode = 1;
});
