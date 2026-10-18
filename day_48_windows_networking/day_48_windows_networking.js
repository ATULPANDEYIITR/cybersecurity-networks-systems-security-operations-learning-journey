"use strict";

/*
 * Windows networking diagnostics and policy model.
 * Runtime: Node.js 18 or later.
 *
 * This program tests TCP reachability and evaluates a local firewall-policy
 * model. It does not authenticate to SMB, RDP, WinRM, or RPC services.
 */

const net = require("node:net");
const os = require("node:os");
const { performance } = require("node:perf_hooks");
const { setTimeout: delay } = require("node:timers/promises");

const WINDOWS_SERVICES = Object.freeze({
  SMB: Object.freeze({
    ports: [445],
    purpose: "File and printer sharing",
    risk: "Unauthorized access to shares or administrative resources",
  }),
  RDP: Object.freeze({
    ports: [3389],
    purpose: "Remote graphical desktop",
    risk: "Unauthorized interactive access and credential attacks",
  }),
  WinRM: Object.freeze({
    ports: [5985, 5986],
    purpose: "PowerShell remoting and Windows management",
    risk: "Remote administrative command execution",
  }),
  RPC: Object.freeze({
    ports: [135],
    purpose: "RPC endpoint discovery",
    risk: "Exposure of remote management interfaces and dependent services",
  }),
});

function validateTarget(host) {
  if (typeof host !== "string" || host.trim() === "") {
    throw new TypeError("Target must be a non-empty hostname or IP address.");
  }

  const value = host.trim();
  if (/\s/.test(value) || value.length > 253) {
    throw new TypeError("Target contains whitespace or exceeds hostname limits.");
  }

  // Node's IP parser validates IPv4 and IPv6 literals.
  if (net.isIP(value) !== 0) {
    return value;
  }

  const labels = value.replace(/\.$/, "").split(".");
  const valid = labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)
  );

  if (!valid) {
    throw new TypeError(`Invalid hostname: ${value}`);
  }

  return value.replace(/\.$/, "");
}

function validatePort(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new RangeError("Port must be an integer between 1 and 65535.");
  }
}

function probeTcp(host, port, timeoutMs = 2000) {
  validatePort(port);

  if (!Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) {
    throw new RangeError("Timeout must be between 100 and 30000 milliseconds.");
  }

  return new Promise((resolve) => {
    const started = performance.now();
    const socket = new net.Socket();
    let settled = false;

    function finish(reachable, error = null) {
      if (settled) return;
      settled = true;

      const elapsedMs = Number((performance.now() - started).toFixed(2));
      socket.destroy();

      resolve({ host, port, reachable, elapsedMs, error });
    }

    socket.setTimeout(timeoutMs);

    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false, "Connection timed out"));
    socket.once("error", (error) => {
      finish(false, `${error.code || error.name}: ${error.message}`);
    });

    socket.connect({ host, port });
  });
}

async function inspectService(host, serviceName, timeoutMs) {
  const name = serviceName.toUpperCase();
  const service = WINDOWS_SERVICES[name];

  if (!service) {
    throw new RangeError(`Unknown service: ${serviceName}`);
  }

  // Independent probes are run concurrently because their outcomes are
  // independent. Limit concurrency when scanning larger inventories.
  const ports = await Promise.all(
    service.ports.map((port) => probeTcp(host, port, timeoutMs))
  );

  return {
    service: name,
    purpose: service.purpose,
    risk: service.risk,
    ports,
  };
}

class FirewallPolicy {
  constructor({ profile, defaultInbound, rules = [] }) {
    if (!["Domain", "Private", "Public"].includes(profile)) {
      throw new TypeError("Unsupported Windows Firewall profile.");
    }
    if (!["Allow", "Block"].includes(defaultInbound)) {
      throw new TypeError("Inbound default must be Allow or Block.");
    }

    this.profile = profile;
    this.defaultInbound = defaultInbound;
    this.rules = rules.map((rule) => {
      validatePort(rule.port);
      if (!["Allow", "Block"].includes(rule.action)) {
        throw new TypeError("Firewall rule action must be Allow or Block.");
      }
      if (!rule.service) {
        throw new TypeError("Each firewall rule requires a service name.");
      }
      return Object.freeze({ ...rule });
    });
  }

  evaluate({ service, port, profile = this.profile, remoteAddress }) {
    validatePort(port);

    if (!["Domain", "Private", "Public"].includes(profile)) {
      throw new TypeError("Unsupported Windows Firewall profile.");
    }

    // This is an educational first-match policy model, not a full simulation
    // of Windows Firewall rule precedence or Windows Filtering Platform.
    const matchingRule = this.rules.find(
      (rule) =>
        rule.service === service &&
        rule.port === port &&
        rule.profile === profile &&
        (!rule.remoteAddress || rule.remoteAddress === remoteAddress)
    );

    return {
      service,
      port,
      profile,
      remoteAddress,
      decision: matchingRule ? matchingRule.action : this.defaultInbound,
      matchedRule: matchingRule ? matchingRule.name : null,
      modelOnly: true,
    };
  }
}

async function main() {
  const args = process.argv.slice(2);
  const targetIndex = args.indexOf("--host");
  const selfTest = args.includes("--self-test");
  const showPolicy = args.includes("--policy");

  if (selfTest) {
    console.assert(validateTarget("localhost") === "localhost");
    console.assert(validateTarget("192.168.1.10") === "192.168.1.10");

    for (const invalid of ["", "bad host", "-invalid.example"]) {
      let rejected = false;
      try {
        validateTarget(invalid);
      } catch {
        rejected = true;
      }
      console.assert(rejected, `Expected invalid hostname: ${invalid}`);
    }

    console.assert(net.isIP("2001:db8::1") === 6);
    console.log("Input-validation checks completed.");
  }

  if (showPolicy) {
    const policy = new FirewallPolicy({
      profile: "Public",
      defaultInbound: "Block",
      rules: [
        {
          name: "Allow approved RDP gateway",
          service: "RDP",
          port: 3389,
          profile: "Private",
          remoteAddress: "192.168.1.20",
          action: "Allow",
        },
        {
          name: "Block SMB on public networks",
          service: "SMB",
          port: 445,
          profile: "Public",
          action: "Block",
        },
      ],
    });

    console.log(
      JSON.stringify(
        [
          policy.evaluate({
            service: "SMB",
            port: 445,
            profile: "Public",
            remoteAddress: "203.0.113.15",
          }),
          policy.evaluate({
            service: "RDP",
            port: 3389,
            profile: "Private",
            remoteAddress: "192.168.1.20",
          }),
        ],
        null,
        2
      )
    );
  }

  if (targetIndex !== -1) {
    const rawHost = args[targetIndex + 1];
    if (!rawHost || rawHost.startsWith("--")) {
      throw new TypeError("--host requires a hostname or IP address.");
    }

    const host = validateTarget(rawHost);
    const serviceArgIndex = args.indexOf("--services");
    const services =
      serviceArgIndex === -1
        ? Object.keys(WINDOWS_SERVICES)
        : args[serviceArgIndex + 1]?.split(",").map((item) => item.trim().toUpperCase());

    if (!services || services.length === 0 || services.some((s) => !WINDOWS_SERVICES[s])) {
      throw new TypeError("Use --services SMB,RDP,WinRM,RPC.");
    }

    const timeoutIndex = args.indexOf("--timeout");
    const timeoutMs =
      timeoutIndex === -1 ? 2000 : Number(args[timeoutIndex + 1]);

    if (!Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) {
      throw new RangeError("Invalid --timeout value.");
    }

    const report = await Promise.all(
      services.map((service) => inspectService(host, service, timeoutMs))
    );

    console.log(
      JSON.stringify(
        {
          target: host,
          localHostname: os.hostname(),
          generatedAt: new Date().toISOString(),
          limitation:
            "TCP reachability does not establish authentication or protocol health.",
          services: report,
        },
        null,
        2
      )
    );
  }

  if (!selfTest && !showPolicy && targetIndex === -1) {
    console.log(
      "Usage: node windows-networking.js --host localhost " +
        "--services SMB,RDP,WinRM,RPC --timeout 2000"
    );
    console.log("Options: --self-test, --policy");
  }

  // Keep this imported asynchronous timer available for future cancellable
  // maintenance jobs without introducing background network activity.
  await delay(0);
}

main().catch((error) => {
  console.error(`${error.name}: ${error.message}`);
  process.exitCode = 1;
});
