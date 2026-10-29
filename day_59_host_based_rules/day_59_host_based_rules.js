"use strict";

const fs = require("node:fs/promises");
const net = require("node:net");
const EventEmitter = require("node:events");

const Direction = Object.freeze({
  INBOUND: "inbound",
  OUTBOUND: "outbound",
});

const Action = Object.freeze({
  ALLOW: "allow",
  DENY: "deny",
});

const Protocol = Object.freeze({
  TCP: "tcp",
  UDP: "udp",
  ICMP: "icmp",
  ANY: "any",
});

const LogLevel = Object.freeze({
  NONE: "none",
  DENIED: "denied",
  ALL: "all",
});

class FirewallError extends Error {}

class FirewallRule {
  constructor({
    id,
    direction,
    action,
    protocol = Protocol.ANY,
    sourceNetwork = "0.0.0.0/0",
    destinationNetwork = "0.0.0.0/0",
    destinationPort = null,
    application = "*",
    priority = 100,
    enabled = true,
    logLevel = LogLevel.DENIED,
    description = "",
  }) {
    if (!id || !id.trim()) throw new FirewallError("Rule id is required");
    if (!Object.values(Direction).includes(direction)) {
      throw new FirewallError(`Invalid direction: ${direction}`);
    }
    if (!Object.values(Action).includes(action)) {
      throw new FirewallError(`Invalid action: ${action}`);
    }
    if (!Object.values(Protocol).includes(protocol)) {
      throw new FirewallError(`Invalid protocol: ${protocol}`);
    }
    if (!Number.isInteger(priority) || priority < 1) {
      throw new FirewallError("Priority must be a positive integer");
    }
    if (
      destinationPort !== null &&
      (!Number.isInteger(destinationPort) ||
        destinationPort < 1 ||
        destinationPort > 65535)
    ) {
      throw new FirewallError("Invalid destination port");
    }

    this.id = id;
    this.direction = direction;
    this.action = action;
    this.protocol = protocol;
    this.sourceNetwork = sourceNetwork;
    this.destinationNetwork = destinationNetwork;
    this.destinationPort = destinationPort;
    this.application = application;
    this.priority = priority;
    this.enabled = enabled;
    this.logLevel = logLevel;
    this.description = description;
  }
}

class Connection {
  constructor({
    direction,
    protocol,
    sourceIp,
    destinationIp,
    sourcePort = null,
    destinationPort = null,
    application,
    user = null,
  }) {
    this.direction = direction;
    this.protocol = protocol;
    this.sourceIp = sourceIp;
    this.destinationIp = destinationIp;
    this.sourcePort = sourcePort;
    this.destinationPort = destinationPort;
    this.application = application;
    this.user = user;
  }
}

function ipv4ToInteger(ip) {
  if (!net.isIPv4(ip)) throw new FirewallError(`Invalid IPv4 address: ${ip}`);
  return ip
    .split(".")
    .reduce((value, octet) => value * 256 + Number(octet), 0) >>> 0;
}

function networkContains(ip, cidr) {
  const [networkAddress, prefixText] = cidr.split("/");
  const prefix = Number(prefixText);

  if (!net.isIPv4(networkAddress) || !Number.isInteger(prefix) ||
      prefix < 0 || prefix > 32) {
    throw new FirewallError(`Invalid IPv4 network: ${cidr}`);
  }

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (
    (ipv4ToInteger(ip) & mask) >>> 0 ===
    (ipv4ToInteger(networkAddress) & mask) >>> 0
  );
}

function applicationMatches(application, pattern) {
  if (pattern === "*") return true;

  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");

  return new RegExp(`^${escaped}$`, "i").test(application);
}

function validateConnection(connection) {
  if (!Object.values(Direction).includes(connection.direction)) {
    throw new FirewallError("Invalid direction");
  }
  if (!Object.values(Protocol).includes(connection.protocol)) {
    throw new FirewallError("Invalid protocol");
  }

  ipv4ToInteger(connection.sourceIp);
  ipv4ToInteger(connection.destinationIp);

  for (const port of [connection.sourcePort, connection.destinationPort]) {
    if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
      throw new FirewallError(`Invalid port: ${port}`);
    }
  }

  if (!connection.application || !connection.application.trim()) {
    throw new FirewallError("Application identity is required");
  }
}

class HostFirewall extends EventEmitter {
  constructor(defaultAction = Action.DENY) {
    super();
    this.defaultAction = defaultAction;
    this.rules = [];
    this.auditLog = [];
  }

  addRule(rule) {
    if (this.rules.some((existing) => existing.id === rule.id)) {
      throw new FirewallError(`Duplicate rule id: ${rule.id}`);
    }

    this.rules.push(rule);
    this.rules.sort((a, b) => a.priority - b.priority);
  }

  matches(connection, rule) {
    if (!rule.enabled) return false;
    if (connection.direction !== rule.direction) return false;
    if (rule.protocol !== Protocol.ANY &&
        connection.protocol !== rule.protocol) return false;
    if (!networkContains(connection.sourceIp, rule.sourceNetwork)) return false;
    if (!networkContains(connection.destinationIp, rule.destinationNetwork)) {
      return false;
    }
    if (
      rule.destinationPort !== null &&
      connection.destinationPort !== rule.destinationPort
    ) {
      return false;
    }
    return applicationMatches(connection.application, rule.application);
  }

  evaluate(connection) {
    validateConnection(connection);

    const matchedRule = this.rules.find((rule) =>
      this.matches(connection, rule)
    );

    const action = matchedRule ? matchedRule.action : this.defaultAction;
    const ruleId = matchedRule ? matchedRule.id : "DEFAULT";
    const logged =
      matchedRule?.logLevel === LogLevel.ALL ||
      (matchedRule?.logLevel === LogLevel.DENIED && action === Action.DENY) ||
      (!matchedRule && action === Action.DENY);

    const decision = Object.freeze({
      timestamp: new Date().toISOString(),
      action,
      ruleId,
      logged,
      reason: matchedRule?.description || "No explicit rule matched",
      connection,
    });

    if (logged) {
      this.auditLog.push(decision);
      this.emit("decision", decision);
    }

    return decision;
  }

  async exportAuditLog(fileName) {
    await fs.writeFile(
      fileName,
      JSON.stringify(this.auditLog, null, 2),
      "utf8"
    );
  }
}

function createFirewall() {
  const firewall = new HostFirewall();

  firewall.addRule(
    new FirewallRule({
      id: "ALLOW-SSH-MGMT",
      direction: Direction.INBOUND,
      action: Action.ALLOW,
      protocol: Protocol.TCP,
      sourceNetwork: "10.20.0.0/24",
      destinationPort: 22,
      application: "sshd",
      priority: 10,
      logLevel: LogLevel.ALL,
      description: "Administrative SSH from the management network",
    })
  );

  firewall.addRule(
    new FirewallRule({
      id: "DENY-INBOUND-APP",
      direction: Direction.INBOUND,
      action: Action.DENY,
      protocol: Protocol.TCP,
      destinationPort: 8080,
      priority: 20,
      logLevel: LogLevel.DENIED,
      description: "Unapproved inbound application service",
    })
  );

  firewall.addRule(
    new FirewallRule({
      id: "ALLOW-DNS",
      direction: Direction.OUTBOUND,
      action: Action.ALLOW,
      protocol: Protocol.UDP,
      destinationNetwork: "10.20.0.53/32",
      destinationPort: 53,
      application: "resolver",
      priority: 30,
      logLevel: LogLevel.ALL,
      description: "Approved DNS resolver",
    })
  );

  firewall.addRule(
    new FirewallRule({
      id: "ALLOW-HTTPS",
      direction: Direction.OUTBOUND,
      action: Action.ALLOW,
      protocol: Protocol.TCP,
      destinationPort: 443,
      application: "browser*",
      priority: 40,
      logLevel: LogLevel.ALL,
      description: "HTTPS from approved browser processes",
    })
  );

  firewall.addRule(
    new FirewallRule({
      id: "DENY-OUTBOUND-UNKNOWN",
      direction: Direction.OUTBOUND,
      action: Action.DENY,
      priority: 90,
      logLevel: LogLevel.DENIED,
      description: "Outbound traffic without an explicit allow rule",
    })
  );

  return firewall;
}

function simulateConnection(firewall, connection) {
  try {
    const decision = firewall.evaluate(new Connection(connection));
    console.log(
      `${connection.direction.padEnd(8)} ` +
      `${connection.application.padEnd(14)} ` +
      `${decision.action.padEnd(5)} ` +
      `rule=${decision.ruleId.padEnd(22)} ` +
      `${decision.reason}`
    );
    return decision;
  } catch (error) {
    console.error(`Connection rejected by validation: ${error.message}`);
    return null;
  }
}

async function main() {
  const firewall = createFirewall();

  firewall.on("decision", (decision) => {
    console.log(
      `[AUDIT] ${decision.timestamp} ${decision.action.toUpperCase()} ` +
      `${decision.ruleId} ${decision.connection.application}`
    );
  });

  const scenarios = [
    {
      direction: Direction.INBOUND,
      protocol: Protocol.TCP,
      sourceIp: "10.20.0.15",
      destinationIp: "10.20.0.10",
      sourcePort: 50000,
      destinationPort: 22,
      application: "sshd",
    },
    {
      direction: Direction.INBOUND,
      protocol: Protocol.TCP,
      sourceIp: "203.0.113.50",
      destinationIp: "10.20.0.10",
      sourcePort: 50001,
      destinationPort: 8080,
      application: "unknown",
    },
    {
      direction: Direction.OUTBOUND,
      protocol: Protocol.UDP,
      sourceIp: "10.20.0.10",
      destinationIp: "10.20.0.53",
      sourcePort: 53000,
      destinationPort: 53,
      application: "resolver",
    },
    {
      direction: Direction.OUTBOUND,
      protocol: Protocol.TCP,
      sourceIp: "10.20.0.10",
      destinationIp: "198.51.100.20",
      sourcePort: 52000,
      destinationPort: 443,
      application: "browser",
    },
    {
      direction: Direction.OUTBOUND,
      protocol: Protocol.TCP,
      sourceIp: "10.20.0.10",
      destinationIp: "198.51.100.40",
      sourcePort: 52001,
      destinationPort: 22,
      application: "unknown",
    },
  ];

  const decisions = scenarios.map((item) =>
    simulateConnection(firewall, item)
  );

  if (decisions[0]?.action !== Action.ALLOW) throw new Error("SSH test failed");
  if (decisions[1]?.action !== Action.DENY) throw new Error("Inbound denial test failed");
  if (decisions[2]?.action !== Action.ALLOW) throw new Error("DNS test failed");
  if (decisions[3]?.action !== Action.ALLOW) throw new Error("HTTPS test failed");
  if (decisions[4]?.action !== Action.DENY) throw new Error("Outbound denial test failed");

  simulateConnection(firewall, {
    direction: Direction.OUTBOUND,
    protocol: Protocol.TCP,
    sourceIp: "invalid-ip",
    destinationIp: "198.51.100.20",
    sourcePort: 50000,
    destinationPort: 443,
    application: "browser",
  });

  await firewall.exportAuditLog("firewall-audit.json");
  console.log(`Audit entries exported: ${firewall.auditLog.length}`);
}

main().catch((error) => {
  console.error(`Fatal error: ${error.message}`);
  process.exitCode = 1;
});
