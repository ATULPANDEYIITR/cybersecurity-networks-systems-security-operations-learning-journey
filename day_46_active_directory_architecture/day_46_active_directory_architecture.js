"use strict";

/*
 * Active Directory architecture through an event-driven directory service
 * model. The example focuses on DNS discovery, LDAP search operations,
 * domain lifecycle events, trust direction, and policy-aware diagnostics.
 *
 * This is a simulation. It does not perform Windows authentication or
 * establish real LDAP, Kerberos, or DNS network connections.
 */

const { EventEmitter } = require("node:events");
const assert = require("node:assert/strict");

class DirectoryError extends Error {}
class ConfigurationError extends DirectoryError {}
class DirectoryNotFoundError extends DirectoryError {}
class ServiceDiscoveryError extends DirectoryError {}

function normalizeDnsName(input) {
  if (typeof input !== "string") {
    throw new ConfigurationError("DNS name must be a string.");
  }

  const name = input.trim().replace(/\.+$/, "").toLowerCase();

  if (!name || name.length > 253) {
    throw new ConfigurationError("DNS name is empty or too long.");
  }

  const labels = name.split(".");
  for (const label of labels) {
    if (
      label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    ) {
      throw new ConfigurationError(`Invalid DNS label: ${label}`);
    }
  }

  return name;
}

function escapeLdapAssertionValue(value) {
  // LDAP filters use special characters with structural meaning.
  // Escaping them prevents untrusted values from changing filter logic.
  return String(value).replace(/[\0()*\\]/g, (character) => {
    const hex = character.charCodeAt(0).toString(16).padStart(2, "0");
    return `\\${hex}`;
  });
}

class DirectoryObject {
  constructor({ dn, objectClass, attributes = {} }) {
    if (!dn || !/^(CN|OU|DC)=/i.test(dn)) {
      throw new ConfigurationError("A valid distinguished name is required.");
    }
    if (!objectClass) {
      throw new ConfigurationError("Object class is required.");
    }

    this.dn = dn;
    this.objectClass = objectClass.toLowerCase();

    // Normalize attribute names once, so queries are case-insensitive.
    this.attributes = new Map(
      Object.entries(attributes).map(([key, value]) => [
        key.toLowerCase(),
        value,
      ]),
    );
  }

  get(attributeName) {
    return this.attributes.get(attributeName.toLowerCase());
  }
}

class Domain {
  constructor({ name, forestRoot, parent = null }) {
    this.name = normalizeDnsName(name);
    this.forestRoot = normalizeDnsName(forestRoot);
    this.parent = parent ? normalizeDnsName(parent) : null;
    this.objects = new Map();
    this.revision = 0;
  }

  addObject(directoryObject) {
    const key = directoryObject.dn.toLowerCase();
    if (this.objects.has(key)) {
      throw new ConfigurationError(`Duplicate DN: ${directoryObject.dn}`);
    }

    this.objects.set(key, directoryObject);
    this.revision += 1;
  }

  search({ objectClass, attribute, equals } = {}) {
    const expectedClass = objectClass?.toLowerCase();
    const expectedAttribute = attribute?.toLowerCase();
    const expectedValue = equals?.toLowerCase();

    return [...this.objects.values()].filter((object) => {
      if (expectedClass && object.objectClass !== expectedClass) {
        return false;
      }

      if (expectedAttribute) {
        const value = object.get(expectedAttribute);
        const values = Array.isArray(value) ? value : [value];
        return values.some(
          (item) =>
            typeof item === "string" &&
            item.toLowerCase() === expectedValue,
        );
      }

      return true;
    });
  }

  get baseDn() {
    return this.name
      .split(".")
      .map((label) => `DC=${label}`)
      .join(",");
  }
}

class Forest {
  constructor(rootDomain) {
    this.rootDomain = normalizeDnsName(rootDomain);
    this.domains = new Map();
  }

  addDomain(domain) {
    if (domain.forestRoot !== this.rootDomain) {
      throw new ConfigurationError("Domain belongs to another forest.");
    }
    if (this.domains.has(domain.name)) {
      throw new ConfigurationError(`Duplicate domain: ${domain.name}`);
    }

    if (this.domains.size === 0) {
      if (domain.name !== this.rootDomain || domain.parent !== null) {
        throw new ConfigurationError(
          "First domain must be the forest root.",
        );
      }
    } else {
      const parent = this.domains.get(domain.parent);
      if (!parent || !domain.name.endsWith(`.${parent.name}`)) {
        throw new ConfigurationError(
          "Child domain must have a valid existing parent.",
        );
      }
    }

    this.domains.set(domain.name, domain);
  }
}

class DnsCatalog {
  constructor() {
    this.records = new Map();
  }

  addSrv({ name, target, port, priority = 0, weight = 100 }) {
    const queryName = normalizeDnsName(name);
    const normalizedTarget = normalizeDnsName(target);

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new ConfigurationError("Invalid service port.");
    }
    if (priority < 0 || weight < 0) {
      throw new ConfigurationError("Priority and weight cannot be negative.");
    }

    const record = Object.freeze({
      type: "SRV",
      name: queryName,
      target: normalizedTarget,
      port,
      priority,
      weight,
    });

    const existing = this.records.get(queryName) ?? [];
    existing.push(record);
    this.records.set(queryName, existing);
  }

  lookupSrv(name) {
    const query = normalizeDnsName(name);
    return [...(this.records.get(query) ?? [])].sort(
      (a, b) => a.priority - b.priority || b.weight - a.weight,
    );
  }
}

class TrustGraph {
  constructor() {
    this.edges = new Map();
  }

  addTrust({ source, target, direction, transitive = true, enabled = true }) {
    const from = normalizeDnsName(source);
    const to = normalizeDnsName(target);

    if (from === to) {
      throw new ConfigurationError("Self-trust is not allowed.");
    }

    const allowedDirections = new Set(["outbound", "inbound", "bidirectional"]);
    if (!allowedDirections.has(direction)) {
      throw new ConfigurationError("Invalid trust direction.");
    }

    if (enabled) {
      if (direction === "outbound" || direction === "bidirectional") {
        this.addEdge(from, to, transitive);
      }
      if (direction === "inbound" || direction === "bidirectional") {
        this.addEdge(to, from, transitive);
      }
    }
  }

  addEdge(from, to, transitive) {
    if (!this.edges.has(from)) this.edges.set(from, []);
    this.edges.get(from).push({ target: to, transitive });
  }

  canReach(source, target) {
    const from = normalizeDnsName(source);
    const to = normalizeDnsName(target);
    if (from === to) return true;

    const queue = [{ name: from, mayContinue: true }];
    const visited = new Set([from]);

    while (queue.length) {
      const current = queue.shift();

      for (const edge of this.edges.get(current.name) ?? []) {
        if (edge.target === to) return true;
        if (!edge.transitive || visited.has(edge.target)) continue;

        visited.add(edge.target);
        queue.push({ name: edge.target, mayContinue: true });
      }
    }

    return false;
  }
}

class DirectoryController extends EventEmitter {
  constructor(forests, dnsCatalog, trustGraph) {
    super();
    this.forests = forests;
    this.dns = dnsCatalog;
    this.trusts = trustGraph;
    this.state = "ready";
    this.operations = 0;
  }

  locateDomain(domainName) {
    const normalized = normalizeDnsName(domainName);

    for (const forest of this.forests.values()) {
      const domain = forest.domains.get(normalized);
      if (domain) return domain;
    }

    throw new DirectoryNotFoundError(`Unknown domain: ${normalized}`);
  }

  discoverDomainControllers(domainName) {
    const domain = normalizeDnsName(domainName);
    const serviceName = `_ldap._tcp.${domain}`;
    const records = this.dns.lookupSrv(serviceName);

    if (records.length === 0) {
      this.emit("discoveryFailed", { domain, serviceName });
      throw new ServiceDiscoveryError(
        `No LDAP SRV records exist for ${serviceName}`,
      );
    }

    this.emit("controllersDiscovered", {
      domain,
      controllers: records.map((record) => record.target),
    });

    return records;
  }

  searchUsers(domainName, department) {
    const domain = this.locateDomain(domainName);
    const controllers = this.discoverDomainControllers(domain.name);

    // Discovery success is a prerequisite in this model, but it does not
    // prove that the LDAP server is reachable or that a bind will succeed.
    this.operations += 1;
    const users = domain.search({
      objectClass: "user",
      attribute: "department",
      equals: department,
    });

    this.emit("ldapSearchCompleted", {
      domain: domain.name,
      baseDn: domain.baseDn,
      controllerCount: controllers.length,
      resultCount: users.length,
    });

    return users;
  }

  canAttemptCrossForestAccess(sourceDomain, targetDomain) {
    const source = this.locateDomain(sourceDomain);
    const target = this.locateDomain(targetDomain);

    if (source.forestRoot === target.forestRoot) return true;
    return this.trusts.canReach(source.forestRoot, target.forestRoot);
  }
}

function createLab() {
  const corporate = new Forest("corp.example.com");
  const root = new Domain({
    name: "corp.example.com",
    forestRoot: "corp.example.com",
  });
  const engineering = new Domain({
    name: "engineering.corp.example.com",
    forestRoot: "corp.example.com",
    parent: "corp.example.com",
  });

  root.addObject(
    new DirectoryObject({
      dn: "OU=ServiceAccounts,DC=corp,DC=example,DC=com",
      objectClass: "organizationalUnit",
      attributes: { ou: "ServiceAccounts" },
    }),
  );

  engineering.addObject(
    new DirectoryObject({
      dn: "CN=Riya Sharma,OU=Engineering,DC=engineering,DC=corp,DC=example,DC=com",
      objectClass: "user",
      attributes: {
        cn: "Riya Sharma",
        sAMAccountName: "riya.sharma",
        department: "Engineering",
        mail: "riya.sharma@corp.example.com",
      },
    }),
  );

  engineering.addObject(
    new DirectoryObject({
      dn: "CN=CI Agent,OU=Computers,DC=engineering,DC=corp,DC=example,DC=com",
      objectClass: "computer",
      attributes: {
        cn: "CI Agent",
        dNSHostName: "ci01.engineering.corp.example.com",
      },
    }),
  );

  corporate.addDomain(root);
  corporate.addDomain(engineering);

  const partner = new Forest("partner.example.net");
  partner.addDomain(
    new Domain({
      name: "partner.example.net",
      forestRoot: "partner.example.net",
    }),
  );

  const forests = new Map([
    [corporate.rootDomain, corporate],
    [partner.rootDomain, partner],
  ]);

  const dns = new DnsCatalog();
  dns.addSrv({
    name: "_ldap._tcp.engineering.corp.example.com",
    target: "dc01.corp.example.com",
    port: 389,
    priority: 0,
    weight: 100,
  });
  dns.addSrv({
    name: "_kerberos._tcp.engineering.corp.example.com",
    target: "dc01.corp.example.com",
    port: 88,
    priority: 0,
    weight: 100,
  });
  dns.addSrv({
    name: "_ldap._tcp.partner.example.net",
    target: "dc01.partner.example.net",
    port: 389,
  });

  const trusts = new TrustGraph();
  trusts.addTrust({
    source: "corp.example.com",
    target: "partner.example.net",
    direction: "bidirectional",
    transitive: true,
  });

  return new DirectoryController(forests, dns, trusts);
}

async function main() {
  const directory = createLab();

  directory.on("controllersDiscovered", (event) => {
    console.log(
      `[DNS] ${event.domain}: ${event.controllers.join(", ")}`,
    );
  });

  directory.on("ldapSearchCompleted", (event) => {
    console.log(
      `[LDAP] base=${event.baseDn}, results=${event.resultCount}`,
    );
  });

  directory.on("discoveryFailed", ({ serviceName }) => {
    console.error(`[DNS] Missing service record: ${serviceName}`);
  });

  console.log("=== Directory Lookup ===");
  const users = directory.searchUsers(
    "engineering.corp.example.com",
    "Engineering",
  );
  console.log(users.map((user) => user.get("mail")));

  console.log("\n=== Trust Evaluation ===");
  console.log(
    "Corporate to partner:",
    directory.canAttemptCrossForestAccess(
      "engineering.corp.example.com",
      "partner.example.net",
    ),
  );

  console.log("\n=== LDAP Filter Safety ===");
  const unsafeValue = "riya*)(objectClass=*)";
  console.log(
    "Escaped assertion:",
    escapeLdapAssertionValue(unsafeValue),
  );

  console.log("\n=== Service Discovery Failure ===");
  try {
    directory.discoverDomainControllers("missing.example.org");
  } catch (error) {
    if (!(error instanceof ServiceDiscoveryError)) throw error;
    console.log(error.message);
  }

  assert.equal(users.length, 1);
  assert.equal(users[0].get("sAMAccountName"), "riya.sharma");
  assert.equal(
    directory.canAttemptCrossForestAccess(
      "corp.example.com",
      "partner.example.net",
    ),
    true,
  );
  assert.equal(
    escapeLdapAssertionValue("*"),
    "\\2a",
  );

  console.log("\nAll directory architecture checks passed.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
