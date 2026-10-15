"use strict";

/*
 * Event-driven Active Directory domain administration simulator.
 *
 * Focus: domain and controller topology, OU placement, group membership,
 * GPO scope, policy precedence, account state, and authorization decisions.
 *
 * This program models directory behavior; it does not implement LDAP,
 * Kerberos, Windows security tokens, or real Group Policy processing.
 */

const { EventEmitter } = require("node:events");
const { randomUUID } = require("node:crypto");
const assert = require("node:assert/strict");

class DirectoryError extends Error {}
class ValidationError extends DirectoryError {}
class DuplicateObjectError extends DirectoryError {}
class NotFoundError extends DirectoryError {}
class AccessDeniedError extends DirectoryError {}

const AccountState = Object.freeze({
  ENABLED: "enabled",
  DISABLED: "disabled",
  LOCKED: "locked",
});

const GroupScope = Object.freeze({
  GLOBAL: "global",
  DOMAIN_LOCAL: "domain-local",
  UNIVERSAL: "universal",
});

class DirectoryObject {
  constructor(name, type, distinguishedName, attributes = {}) {
    this.id = randomUUID();
    this.name = name;
    this.type = type;
    this.distinguishedName = distinguishedName;
    this.attributes = Object.freeze({ ...attributes });
    this.createdAt = new Date();
  }
}

class User extends DirectoryObject {
  constructor(name, samAccountName, department, ouDn) {
    super(name, "user", `CN=${name},${ouDn}`, { department });
    this.samAccountName = samAccountName;
    this.userPrincipalName = `${samAccountName}@corp.example.com`;
    this.state = AccountState.ENABLED;
    this.failedAttempts = 0;
    this.mfaRegistered = false;
  }
}

class SecurityGroup extends DirectoryObject {
  constructor(name, scope, ouDn) {
    super(name, "security-group", `CN=${name},${ouDn}`);
    this.scope = scope;
    this.members = new Set();
  }
}

class OrganizationalUnit extends DirectoryObject {
  constructor(name, parentDn, protectedFromDeletion = true) {
    const dn = parentDn ? `OU=${name},${parentDn}` : name;
    super(name, "organizational-unit", dn);
    this.parentDn = parentDn;
    this.protectedFromDeletion = protectedFromDeletion;
    this.blockInheritance = false;
    this.children = new Set();
  }
}

class DomainController {
  constructor(name, site, roles = []) {
    this.name = name;
    this.site = site;
    this.roles = new Set(roles);
    this.writable = true;
    this.globalCatalog = true;
    this.reachable = true;
    this.usnObserved = 0;
  }
}

class PolicyObject {
  constructor(name, settings) {
    this.id = randomUUID();
    this.name = name;
    this.settings = Object.freeze({ ...settings });
    this.enabled = true;
    this.computerConfigurationEnabled = true;
  }
}

class ActiveDirectoryDomain extends EventEmitter {
  constructor(dnsName, netbiosName) {
    super();

    const dns = dnsName.trim().toLowerCase();
    const labels = dns.split(".");
    const validDns = labels.length >= 2 && labels.every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    );

    if (!validDns) {
      throw new ValidationError("A valid multi-label DNS domain is required.");
    }
    if (!/^[A-Z0-9-]{1,15}$/.test(netbiosName.toUpperCase())) {
      throw new ValidationError("Invalid NetBIOS domain name.");
    }

    this.dnsName = dns;
    this.netbiosName = netbiosName.toUpperCase();
    this.domainDn = labels.map((label) => `DC=${label}`).join(",");
    this.objects = new Map();
    this.users = new Map();
    this.groups = new Map();
    this.ous = new Map();
    this.controllers = new Map();
    this.policies = new Map();
    this.policyLinks = [];
    this.audit = [];
    this.revision = 0;

    this.root = new OrganizationalUnit("Domain Root", null);
    this.root.distinguishedName = this.domainDn;
    this.ous.set(this.domainDn.toLowerCase(), this.root);
    this.objects.set(this.root.id, this.root);
  }

  record(type, subject, details = {}) {
    const event = Object.freeze({
      revision: ++this.revision,
      type,
      subject,
      details: Object.freeze({ ...details }),
      occurredAt: new Date().toISOString(),
    });
    this.audit.push(event);

    // Consumers can subscribe without coupling policy evaluation to logging.
    this.emit("directory-event", event);
    return event;
  }

  addController(controller) {
    const key = controller.name.toLowerCase();
    if (this.controllers.has(key)) {
      throw new DuplicateObjectError(`Controller ${controller.name} already exists.`);
    }
    this.controllers.set(key, controller);
    this.record("controller-added", controller.name, { site: controller.site });
  }

  createOU(name, parentDn = this.domainDn, protect = true) {
    if (!name.trim() || name.includes(",")) {
      throw new ValidationError("OU name must be non-empty and cannot contain commas.");
    }

    const parent = this.ous.get(parentDn.toLowerCase());
    if (!parent) throw new NotFoundError(`Parent OU not found: ${parentDn}`);

    const ou = new OrganizationalUnit(name, parent.distinguishedName, protect);
    const key = ou.distinguishedName.toLowerCase();
    if (this.ous.has(key)) {
      throw new DuplicateObjectError(`OU already exists: ${ou.distinguishedName}`);
    }

    this.ous.set(key, ou);
    this.objects.set(ou.id, ou);
    parent.children.add(ou.id);
    this.record("ou-created", ou.id, { dn: ou.distinguishedName });
    return ou;
  }

  createUser(name, samAccountName, department, ouDn) {
    const sam = samAccountName.trim();
    if (!/^[A-Za-z0-9._-]{1,20}$/.test(sam)) {
      throw new ValidationError("Account name must use 1-20 permitted characters.");
    }
    if (this.users.has(sam.toLowerCase())) {
      throw new DuplicateObjectError(`Account name already exists: ${sam}`);
    }

    const ou = this.ous.get(ouDn.toLowerCase());
    if (!ou) throw new NotFoundError(`OU not found: ${ouDn}`);
    if (!department.trim()) throw new ValidationError("Department is required.");

    const user = new User(name.trim(), sam, department.trim(), ou.distinguishedName);
    this.users.set(sam.toLowerCase(), user);
    this.objects.set(user.id, user);
    this.record("user-created", user.id, {
      dn: user.distinguishedName,
      department: user.attributes.department,
    });
    return user;
  }

  createGroup(name, scope, ouDn) {
    if (!Object.values(GroupScope).includes(scope)) {
      throw new ValidationError(`Unsupported group scope: ${scope}`);
    }
    const ou = this.ous.get(ouDn.toLowerCase());
    if (!ou) throw new NotFoundError(`OU not found: ${ouDn}`);

    const group = new SecurityGroup(name.trim(), scope, ou.distinguishedName);
    if (!group.name) throw new ValidationError("Group name is required.");

    this.groups.set(group.id, group);
    this.objects.set(group.id, group);
    this.record("group-created", group.id, { scope });
    return group;
  }

  addMember(groupId, memberId) {
    const group = this.groups.get(groupId);
    const member = this.objects.get(memberId);
    if (!group || !member) throw new NotFoundError("Group or member was not found.");
    if (groupId === memberId) throw new ValidationError("Self-membership is forbidden.");

    if (member instanceof SecurityGroup && this.containsGroup(member.id, groupId)) {
      throw new ValidationError("Nested membership would create a cycle.");
    }

    group.members.add(memberId);
    this.record("group-member-added", groupId, { memberId });
  }

  containsGroup(startId, targetId, visited = new Set()) {
    if (startId === targetId) return true;
    if (visited.has(startId)) return false;
    visited.add(startId);

    const group = this.groups.get(startId);
    if (!group) return false;

    for (const memberId of group.members) {
      if (this.groups.has(memberId) &&
          this.containsGroup(memberId, targetId, visited)) {
        return true;
      }
    }
    return false;
  }

  effectiveGroups(principalId) {
    if (!this.objects.has(principalId)) {
      throw new NotFoundError("Principal was not found.");
    }

    const result = new Set();
    const visited = new Set();
    const pending = [principalId];

    while (pending.length > 0) {
      const currentId = pending.pop();
      if (visited.has(currentId)) continue;
      visited.add(currentId);

      for (const group of this.groups.values()) {
        if (group.members.has(currentId) && !result.has(group.id)) {
          result.add(group.id);
          pending.push(group.id);
        }
      }
    }
    return result;
  }

  registerPolicy(policy) {
    for (const [name, value] of Object.entries(policy.settings)) {
      if (name === "passwordMinLength" &&
          (!Number.isInteger(value) || value < 8 || value > 128)) {
        throw new ValidationError("Password minimum length must be 8-128.");
      }
      if (["requireMfa", "firewallEnabled", "usbStorageAllowed"].includes(name) &&
          typeof value !== "boolean") {
        throw new ValidationError(`${name} must be Boolean.`);
      }
      if (name === "screenLockMinutes" &&
          (!Number.isInteger(value) || value < 1 || value > 240)) {
        throw new ValidationError("Screen lock must be 1-240 minutes.");
      }
    }

    this.policies.set(policy.id, policy);
    this.record("policy-registered", policy.id, { name: policy.name });
  }

  linkPolicy(policyId, targetDn, { order = 1, enforced = false } = {}) {
    if (!this.policies.has(policyId)) throw new NotFoundError("Policy not found.");
    if (!this.ous.has(targetDn.toLowerCase())) {
      throw new NotFoundError("Policy target OU not found.");
    }
    if (!Number.isInteger(order) || order < 1) {
      throw new ValidationError("Link order must be a positive integer.");
    }

    this.policyLinks.push({
      policyId,
      targetDn,
      order,
      enforced,
      disabled: false,
    });
    this.record("policy-linked", policyId, { targetDn, order, enforced });
  }

  ancestorChain(targetDn) {
    let current = this.ous.get(targetDn.toLowerCase());
    if (!current) throw new NotFoundError("Policy target was not found.");

    const chain = [];
    while (current) {
      chain.unshift(current);
      current = current.parentDn
        ? this.ous.get(current.parentDn.toLowerCase())
        : null;
    }
    return chain;
  }

  effectiveComputerPolicy(targetDn) {
    const chain = this.ancestorChain(targetDn);
    const effective = {};
    const enforced = {};

    for (const ou of chain) {
      const links = this.policyLinks
        .filter((link) =>
          !link.disabled &&
          link.targetDn.toLowerCase() === ou.distinguishedName.toLowerCase()
        )
        .sort((a, b) => b.order - a.order);

      for (const link of links) {
        const policy = this.policies.get(link.policyId);
        if (!policy?.enabled || !policy.computerConfigurationEnabled) continue;

        for (const [setting, value] of Object.entries(policy.settings)) {
          if (link.enforced) {
            enforced[setting] = value;
          } else if (!(setting in enforced)) {
            effective[setting] = value;
          }
        }
      }
    }

    return Object.freeze({ ...effective, ...enforced });
  }

  authorize(principalId, requiredGroupId) {
    const principal = this.objects.get(principalId);
    if (!principal) throw new NotFoundError("Principal was not found.");
    if (principal instanceof User && principal.state !== AccountState.ENABLED) {
      throw new AccessDeniedError(`Account state is ${principal.state}.`);
    }
    if (!this.groups.has(requiredGroupId)) {
      throw new NotFoundError("Required security group was not found.");
    }

    const memberships = this.effectiveGroups(principalId);
    if (!memberships.has(requiredGroupId)) {
      this.record("access-denied", principalId, { requiredGroupId });
      throw new AccessDeniedError("Required group membership is missing.");
    }

    this.record("access-granted", principalId, { requiredGroupId });
    return true;
  }

  disableUser(samAccountName) {
    const user = this.users.get(samAccountName.toLowerCase());
    if (!user) throw new NotFoundError("User not found.");
    user.state = AccountState.DISABLED;
    this.record("user-disabled", user.id);
  }

  replicationStatus() {
    return [...this.controllers.values()].map((controller) => ({
      controller: controller.name,
      site: controller.site,
      reachable: controller.reachable,
      observedRevision: controller.usnObserved,
      currentRevision: this.revision,
      lag: Math.max(0, this.revision - controller.usnObserved),
    }));
  }
}

function runLab() {
  const domain = new ActiveDirectoryDomain("corp.example.com", "CORP");

  // The event stream provides a clear audit boundary for external consumers.
  let observedEvents = 0;
  domain.on("directory-event", () => observedEvents++);

  const dc01 = new DomainController("DC01", "Lucknow", ["PDC Emulator"]);
  const dc02 = new DomainController("DC02", "Delhi", []);
  domain.addController(dc01);
  domain.addController(dc02);

  const engineering = domain.createOU("Engineering");
  const privileged = domain.createOU("Privileged", engineering.distinguishedName);
  const employees = domain.createOU("Employees");

  const riya = domain.createUser(
    "Riya Sharma", "riya.sharma", "Engineering", engineering.distinguishedName
  );
  const serviceAdmin = domain.createUser(
    "Release Operator", "release.operator", "IT", privileged.distinguishedName
  );

  const engineers = domain.createGroup(
    "Engineering-Developers", GroupScope.GLOBAL, engineering.distinguishedName
  );
  const productionAdmins = domain.createGroup(
    "Production-Admins", GroupScope.DOMAIN_LOCAL, privileged.distinguishedName
  );

  domain.addMember(engineers.id, riya.id);
  domain.addMember(productionAdmins.id, serviceAdmin.id);
  domain.addMember(productionAdmins.id, engineers.id);

  console.log(`Domain: ${domain.dnsName}`);
  console.log(`Domain DN: ${domain.domainDn}`);
  console.log(`Riya DN: ${riya.distinguishedName}`);

  try {
    domain.authorize(riya.id, productionAdmins.id);
  } catch (error) {
    assert.ok(error instanceof AccessDeniedError);
    console.log(`Riya production access: denied (${error.message})`);
  }

  assert.equal(domain.authorize(serviceAdmin.id, productionAdmins.id), true);
  console.log("Release operator production access: granted.");

  const baseline = new PolicyObject("Security Baseline", {
    passwordMinLength: 14,
    requireMfa: true,
    firewallEnabled: true,
    usbStorageAllowed: false,
    screenLockMinutes: 10,
  });
  domain.registerPolicy(baseline);
  domain.linkPolicy(baseline.id, domain.domainDn, { enforced: true });

  const engineeringSettings = new PolicyObject("Engineering Workstations", {
    usbStorageAllowed: true,
    screenLockMinutes: 20,
  });
  domain.registerPolicy(engineeringSettings);
  domain.linkPolicy(engineeringSettings.id, engineering.distinguishedName);

  console.log("Engineering effective computer policy:");
  console.log(domain.effectiveComputerPolicy(engineering.distinguishedName));

  try {
    domain.addMember(engineers.id, productionAdmins.id);
  } catch (error) {
    console.log(`Circular nesting rejected: ${error.message}`);
  }

  try {
    domain.createUser(
      "Duplicate Identity",
      "RIYA.SHARMA",
      "Engineering",
      employees.distinguishedName
    );
  } catch (error) {
    console.log(`Duplicate account rejected: ${error.message}`);
  }

  domain.disableUser("riya.sharma");
  try {
    domain.authorize(riya.id, engineers.id);
  } catch (error) {
    console.log(`Disabled user rejected: ${error.message}`);
  }

  dc01.usnObserved = domain.revision;
  dc02.usnObserved = domain.revision - 4;

  console.log("Controller replication observations:");
  console.log(domain.replicationStatus());
  console.log(`Audit records observed through events: ${observedEvents}`);
  console.log(`Retained audit records: ${domain.audit.length}`);
}

if (require.main === module) {
  try {
    runLab();
  } catch (error) {
    console.error(`Laboratory failed: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = {
  ActiveDirectoryDomain,
  AccountState,
  DomainController,
  GroupScope,
  PolicyObject,
};
