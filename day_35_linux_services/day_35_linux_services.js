#!/usr/bin/env node
"use strict";

/*
 * Linux Services: a JavaScript event-driven model of systemd-style service
 * lifecycle, daemon events, configuration, startup targets, and health checks.
 *
 * This program is intentionally safe to run with Node.js on any operating
 * system. It models systemd behavior rather than modifying the host's services.
 */

const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const ServiceState = Object.freeze({
  INACTIVE: "inactive",
  ACTIVATING: "activating",
  ACTIVE: "active",
  DEACTIVATING: "deactivating",
  FAILED: "failed",
});

const StartupState = Object.freeze({
  DISABLED: "disabled",
  ENABLED: "enabled",
  STATIC: "static",
});

class ServiceError extends Error {
  constructor(message, serviceName = null) {
    super(message);
    this.name = "ServiceError";
    this.serviceName = serviceName;
  }
}

class ServiceConfig {
  constructor({
    name,
    description,
    execStart,
    restart = "no",
    restartSec = 1,
    user = null,
    workingDirectory = null,
    environment = {},
    after = [],
    wantedBy = "multi-user.target",
  }) {
    this.name = name;
    this.description = description;
    this.execStart = [...execStart];
    this.restart = restart;
    this.restartSec = restartSec;
    this.user = user;
    this.workingDirectory = workingDirectory;
    this.environment = { ...environment };
    this.after = [...after];
    this.wantedBy = wantedBy;
  }

  validate() {
    if (!this.name.endsWith(".service")) {
      throw new ServiceError("Service unit names must end with .service", this.name);
    }

    if (this.execStart.length === 0) {
      throw new ServiceError("ExecStart cannot be empty", this.name);
    }

    if (!["no", "on-failure", "always"].includes(this.restart)) {
      throw new ServiceError(`Unsupported restart policy: ${this.restart}`, this.name);
    }

    if (!Number.isFinite(this.restartSec) || this.restartSec < 0) {
      throw new ServiceError("restartSec must be a non-negative number", this.name);
    }

    if (!this.wantedBy) {
      throw new ServiceError("wantedBy must not be empty", this.name);
    }
  }

  toUnitFile() {
    this.validate();

    const lines = [
      "[Unit]",
      `Description=${this.description}`,
    ];

    if (this.after.length > 0) {
      lines.push(`After=${this.after.join(" ")}`);
    }

    lines.push("", "[Service]");
    lines.push("Type=simple");
    lines.push(`ExecStart=${this.execStart.map(shellQuote).join(" ")}`);
    lines.push(`Restart=${this.restart}`);
    lines.push(`RestartSec=${this.restartSec}`);

    if (this.user) {
      lines.push(`User=${this.user}`);
    }

    if (this.workingDirectory) {
      lines.push(`WorkingDirectory=${this.workingDirectory}`);
    }

    for (const [key, value] of Object.entries(this.environment).sort()) {
      lines.push(`Environment=${key}=${quoteSystemdValue(String(value))}`);
    }

    lines.push("", "[Install]", `WantedBy=${this.wantedBy}`);
    return lines.join("\n");
  }
}

function shellQuote(value) {
  if (/^[A-Za-z0-9_./:=+-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function quoteSystemdValue(value) {
  if (/^[A-Za-z0-9_./:=+-]+$/.test(value)) return value;
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

class Daemon extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.state = ServiceState.INACTIVE;
    this.startupState = StartupState.DISABLED;
    this.restartCount = 0;
    this.logs = [];
    this.failureReason = null;
  }

  log(message) {
    const entry = {
      timestamp: new Date().toISOString(),
      service: this.config.name,
      message,
    };
    this.logs.push(entry);
    this.emit("log", entry);
  }

  async start(manager) {
    if (this.state === ServiceState.ACTIVE) {
      this.log("start request ignored because service is already active");
      return;
    }

    this.config.validate();

    for (const dependency of this.config.after) {
      const dependencyService = manager.services.get(dependency);

      if (!dependencyService) {
        this.fail(`missing dependency ${dependency}`);
        return;
      }

      if (dependencyService.state !== ServiceState.ACTIVE) {
        await dependencyService.start(manager);
      }

      if (dependencyService.state !== ServiceState.ACTIVE) {
        this.fail(`dependency ${dependency} did not become active`);
        return;
      }
    }

    this.state = ServiceState.ACTIVATING;
    this.emit("state", this.state);
    this.log("daemon activation started");

    /*
     * Real systemd supervises a process. This model represents process
     * activation with an event-driven transition and does not spawn a daemon.
     */
    await Promise.resolve();

    if (this.config.execStart[0] === "FAIL") {
      this.fail("simulated ExecStart failure");
      return;
    }

    this.failureReason = null;
    this.state = ServiceState.ACTIVE;
    this.emit("state", this.state);
    this.log("daemon entered active state");
  }

  async stop() {
    if (this.state === ServiceState.INACTIVE) {
      this.log("stop request ignored because service is already inactive");
      return;
    }

    this.state = ServiceState.DEACTIVATING;
    this.emit("state", this.state);
    this.log("daemon deactivation started");

    await Promise.resolve();

    this.state = ServiceState.INACTIVE;
    this.emit("state", this.state);
    this.log("daemon entered inactive state");
  }

  async restart(manager) {
    this.log("restart requested");
    await this.stop();
    this.restartCount += 1;
    await this.start(manager);
  }

  enable() {
    this.startupState = StartupState.ENABLED;
    this.log(`enabled through ${this.config.wantedBy}`);
  }

  disable() {
    this.startupState = StartupState.DISABLED;
    this.log("disabled from startup");
  }

  fail(reason) {
    this.failureReason = reason;
    this.state = ServiceState.FAILED;
    this.emit("state", this.state);
    this.log(`service failed: ${reason}`);
  }

  status() {
    return {
      name: this.config.name,
      description: this.config.description,
      state: this.state,
      startup: this.startupState,
      restartCount: this.restartCount,
      failureReason: this.failureReason,
    };
  }
}

class ServiceManager extends EventEmitter {
  constructor() {
    super();
    this.services = new Map();
  }

  register(daemon) {
    if (this.services.has(daemon.config.name)) {
      throw new ServiceError("Duplicate service registration", daemon.config.name);
    }

    daemon.config.validate();
    this.services.set(daemon.config.name, daemon);

    daemon.on("state", (state) => {
      this.emit("service-state", {
        service: daemon.config.name,
        state,
      });
    });
  }

  async boot() {
    this.emit("boot", "multi-user.target reached");

    for (const daemon of this.services.values()) {
      if (daemon.startupState === StartupState.ENABLED) {
        await daemon.start(this);
      }
    }
  }

  status(name) {
    const daemon = this.services.get(name);
    if (!daemon) throw new ServiceError("Unknown service", name);
    return daemon.status();
  }
}

class HealthMonitor {
  constructor(manager) {
    this.manager = manager;
    this.checks = new Map();
  }

  register(name, check) {
    if (!this.manager.services.has(name)) {
      throw new ServiceError("Cannot monitor an unknown service", name);
    }
    this.checks.set(name, check);
  }

  async run() {
    const results = [];

    for (const [name, check] of this.checks) {
      try {
        const healthy = await check();
        results.push({ service: name, healthy: Boolean(healthy) });
      } catch (error) {
        results.push({
          service: name,
          healthy: false,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return results;
  }
}

async function demonstrate() {
  console.log("Linux Services: event-driven systemd-style model");

  const manager = new ServiceManager();

  manager.on("boot", (message) => {
    console.log(`[boot] ${message}`);
  });

  manager.on("service-state", ({ service, state }) => {
    console.log(`[state] ${service} -> ${state}`);
  });

  const networkTarget = new Daemon(
    new ServiceConfig({
      name: "network-online.target.service",
      description: "Network availability target",
      execStart: ["/bin/true"],
    }),
  );
  networkTarget.startupState = StartupState.STATIC;

  const api = new Daemon(
    new ServiceConfig({
      name: "orders-api.service",
      description: "Orders API daemon",
      execStart: ["/opt/orders/bin/server", "--port", "8080"],
      restart: "on-failure",
      restartSec: 4,
      user: "orders",
      workingDirectory: "/opt/orders",
      environment: {
        APP_ENV: "production",
        LOG_LEVEL: "info",
      },
      after: ["network-online.target.service"],
      wantedBy: "multi-user.target",
    }),
  );

  manager.register(networkTarget);
  manager.register(api);
  api.enable();

  console.log("\nService unit configuration:");
  console.log(api.config.toUnitFile());

  console.log("\nBoot simulation:");
  await manager.boot();

  console.log("\nCurrent status:");
  console.log(JSON.stringify(manager.status("orders-api.service"), null, 2));

  const monitor = new HealthMonitor(manager);
  monitor.register("orders-api.service", async () => {
    return manager.status("orders-api.service").state === ServiceState.ACTIVE;
  });

  console.log("\nHealth check:");
  console.log(await monitor.run());

  console.log("\nAsynchronous restart:");
  await api.restart(manager);
  console.log(JSON.stringify(api.status(), null, 2));

  console.log("\nConfiguration failure:");
  const broken = new Daemon(
    new ServiceConfig({
      name: "broken-daemon.service",
      description: "Intentional failure example",
      execStart: ["FAIL", "--config", "/etc/broken.conf"],
      restart: "on-failure",
    }),
  );

  manager.register(broken);
  await broken.start(manager);
  console.log(JSON.stringify(broken.status(), null, 2));

  console.log("\nRecorded daemon events:");
  for (const event of api.logs.slice(-5)) {
    console.log(`${event.timestamp} ${event.message}`);
  }

  console.log("\nRuntime context:");
  console.log(`Node.js: ${process.version}`);
  console.log(`Platform: ${os.platform()}`);
  console.log(`Architecture: ${os.arch()}`);

  /*
   * The unit file is written only to a temporary directory. Installing a
   * service into /etc/systemd/system requires deliberate administrative action
   * and is intentionally outside this executable demonstration.
   */
  const temporaryUnitPath = path.join(
    os.tmpdir(),
    "orders-api.service",
  );

  await fs.writeFile(
    temporaryUnitPath,
    api.config.toUnitFile() + "\n",
    "utf8",
  );

  console.log(`\nTemporary unit file: ${temporaryUnitPath}`);

  console.log("\nOperational distinctions:");
  console.log("systemd manages units, dependencies, activation, supervision, and targets.");
  console.log("A daemon is the long-running process whose lifecycle is supervised.");
  console.log("A service unit declares how that daemon should be started and managed.");
  console.log("Startup enablement associates a service with a target reached during boot.");
}

demonstrate().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
