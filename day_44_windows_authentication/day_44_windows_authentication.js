"use strict";

/*
 * Windows Authentication: event-driven authentication workflow model.
 *
 * Runtime: Node.js 18 or later.
 *
 * The implementation models local logon, NTLM challenge-response
 * concepts, Kerberos ticket exchanges, authentication events, and
 * resource authorization. It does not communicate with Windows,
 * Active Directory, an NTLM endpoint, or a Kerberos KDC.
 */

const crypto = require("node:crypto");
const { promisify } = require("node:util");
const scrypt = promisify(crypto.scrypt);

class AuthenticationError extends Error {}
class AuthorizationError extends Error {}

const AccountKind = Object.freeze({
  LOCAL: "local",
  DOMAIN: "domain",
  SERVICE: "service",
});

const Protocol = Object.freeze({
  LOCAL: "LOCAL",
  NTLM: "NTLM_CONCEPT",
  KERBEROS: "KERBEROS_CONCEPT",
});

const PullSafeAccountName = (value) =>
  typeof value === "string" && value.trim().length > 0;

function normalizePrincipal(username, domain = null) {
  if (!PullSafeAccountName(username)) {
    throw new TypeError("Username must be a non-empty string.");
  }
  return domain
    ? `${domain.toUpperCase()}\\${username.toLowerCase()}`
    : `LOCALHOST\\${username.toLowerCase()}`;
}

function timingSafeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

class AuditTrail extends EventEmitterShim {
  constructor() {
    super();
    this.events = [];
    this.on("authentication", (event) => this.events.push(event));
  }

  record(type, principal, outcome, details) {
    // Never place passwords, session keys, or challenge responses in logs.
    this.emit("authentication", Object.freeze({
      timestamp: new Date().toISOString(),
      type,
      principal,
      outcome,
      details,
    }));
  }
}

/*
 * A small event emitter keeps the example self-contained while showing
 * how authentication events can drive auditing and monitoring.
 */
class EventEmitterShim {
  constructor() {
    this.listeners = new Map();
  }

  on(eventName, callback) {
    if (!this.listeners.has(eventName)) {
      this.listeners.set(eventName, []);
    }
    this.listeners.get(eventName).push(callback);
  }

  emit(eventName, value) {
    for (const callback of this.listeners.get(eventName) ?? []) {
      callback(value);
    }
  }
}

class AccountStore {
  constructor() {
    this.accounts = new Map();
  }

  async create({
    username,
    password,
    kind,
    domain = null,
    groups = [],
  }) {
    if (!PullSafeAccountName(username) || !password) {
      throw new TypeError("A username and password are required.");
    }
    if (!Object.values(AccountKind).includes(kind)) {
      throw new TypeError("Unknown account type.");
    }
    if (kind === AccountKind.DOMAIN && !domain) {
      throw new TypeError("Domain accounts require a domain.");
    }
    if (kind === AccountKind.LOCAL && domain) {
      throw new TypeError("Local accounts cannot specify a domain.");
    }

    const principal = normalizePrincipal(username, domain);
    if (this.accounts.has(principal)) {
      throw new Error(`Duplicate account: ${principal}`);
    }

    const salt = crypto.randomBytes(16);
    const verifier = await scrypt(password, salt, 32, {
      N: 16384,
      r: 8,
      p: 1,
    });

    const account = {
      username,
      domain,
      principal,
      kind,
      salt,
      verifier,
      enabled: true,
      locked: false,
      failedAttempts: 0,
      groups: new Set(groups),
    };

    this.accounts.set(principal, account);
    return account;
  }

  get(username, domain = null) {
    const principal = normalizePrincipal(username, domain);
    const account = this.accounts.get(principal);
    if (!account) throw new AuthenticationError("Unknown account.");
    return account;
  }

  async verify(account, password) {
    const candidate = await scrypt(password, account.salt, 32, {
      N: 16384,
      r: 8,
      p: 1,
    });
    return timingSafeEqual(candidate, account.verifier);
  }
}

class SessionFactory {
  static create(account, protocol, logonType) {
    return Object.freeze({
      principal: account.principal,
      protocol,
      logonType,
      groups: Object.freeze([...account.groups]),
      createdAt: new Date().toISOString(),
      sessionId: crypto.randomUUID(),
    });
  }
}

class LocalLogonService {
  constructor(store, audit, lockoutThreshold = 3) {
    if (!Number.isInteger(lockoutThreshold) || lockoutThreshold < 1) {
      throw new TypeError("Lockout threshold must be a positive integer.");
    }
    this.store = store;
    this.audit = audit;
    this.lockoutThreshold = lockoutThreshold;
  }

  async authenticate(username, password) {
    let account;

    try {
      account = this.store.get(username);
    } catch (error) {
      this.audit.record(
        "local-logon",
        `LOCALHOST\\${username}`,
        "denied",
        "Unknown local account",
      );
      throw error;
    }

    if (account.kind !== AccountKind.LOCAL) {
      throw new AuthenticationError("A local account is required.");
    }
    if (!account.enabled || account.locked) {
      throw new AuthenticationError("Account is unavailable.");
    }

    if (!(await this.store.verify(account, password))) {
      account.failedAttempts += 1;
      if (account.failedAttempts >= this.lockoutThreshold) {
        account.locked = true;
      }
      this.audit.record(
        "local-logon",
        account.principal,
        "denied",
        "Invalid password",
      );
      throw new AuthenticationError("Invalid credentials.");
    }

    account.failedAttempts = 0;
    this.audit.record(
      "local-logon",
      account.principal,
      "success",
      "Local interactive logon model",
    );
    return SessionFactory.create(account, Protocol.LOCAL, "interactive");
  }
}

class NtlmExchange {
  constructor(store, audit, lifetimeMs = 60000) {
    this.store = store;
    this.audit = audit;
    this.lifetimeMs = lifetimeMs;
    this.challenges = new Map();
  }

  issueChallenge(serverName) {
    if (!PullSafeAccountName(serverName)) {
      throw new TypeError("Server name is required.");
    }

    const challenge = Object.freeze({
      id: crypto.randomUUID(),
      serverName,
      nonce: crypto.randomBytes(32),
      issuedAt: Date.now(),
    });
    this.challenges.set(challenge.id, challenge);
    return challenge;
  }

  static makeResponse(password, challenge, username, domain) {
    /*
     * HMAC-SHA256 is used as an illustrative keyed response.
     * Real NTLM uses different protocol-specific derivation and
     * message formats. This is not wire-compatible with NTLM.
     */
    const key = crypto.createHash("sha256").update(password).digest();
    const message = Buffer.concat([
      challenge.nonce,
      Buffer.from(
        `|${challenge.serverName}|${username.toLowerCase()}|${domain.toUpperCase()}`,
      ),
    ]);
    return crypto.createHmac("sha256", key).update(message).digest();
  }

  async authenticate({
    username,
    domain,
    password,
    challengeId,
    response,
  }) {
    // Consume before validating: even failed attempts cannot reuse a nonce.
    const challenge = this.challenges.get(challengeId);
    this.challenges.delete(challengeId);

    const principal = normalizePrincipal(username, domain);
    if (!challenge) {
      throw new AuthenticationError("Challenge is missing or consumed.");
    }
    if (Date.now() - challenge.issuedAt > this.lifetimeMs) {
      throw new AuthenticationError("Challenge expired.");
    }

    const account = this.store.get(username, domain);
    if (account.kind !== AccountKind.DOMAIN) {
      throw new AuthenticationError("A domain account is required.");
    }
    if (!account.enabled || account.locked) {
      throw new AuthenticationError("Account is unavailable.");
    }

    const expected = NtlmExchange.makeResponse(
      password,
      challenge,
      username,
      domain,
    );

    if (!timingSafeEqual(expected, response)) {
      this.audit.record(
        "ntlm-concept",
        principal,
        "denied",
        "Challenge-response mismatch",
      );
      throw new AuthenticationError("Invalid response.");
    }

    this.audit.record(
      "ntlm-concept",
      principal,
      "success",
      "Synthetic challenge-response accepted",
    );
    return SessionFactory.create(account, Protocol.NTLM, "network");
  }
}

class KerberosTicketAuthority {
  constructor(store, audit, ticketLifetimeMs = 300000) {
    this.store = store;
    this.audit = audit;
    this.ticketLifetimeMs = ticketLifetimeMs;
    this.tickets = new Map();
  }

  async authenticateInitialCredentials(username, domain, password) {
    const account = this.store.get(username, domain);
    if (account.kind !== AccountKind.DOMAIN) {
      throw new AuthenticationError("A domain account is required.");
    }
    if (!account.enabled || account.locked) {
      throw new AuthenticationError("Account is unavailable.");
    }
    if (!(await this.store.verify(account, password))) {
      throw new AuthenticationError("Initial authentication failed.");
    }

    // Represents the AS exchange that yields a Ticket Granting Ticket.
    return this.#issue(account.principal, `krbtgt/${domain.toUpperCase()}`, "TGT");
  }

  requestServiceTicket(tgtId, servicePrincipal) {
    const tgt = this.tickets.get(tgtId);
    if (!tgt || tgt.kind !== "TGT") {
      throw new AuthenticationError("Valid TGT required.");
    }
    if (Date.now() >= tgt.expiresAt) {
      throw new AuthenticationError("TGT expired.");
    }
    if (!/^([A-Za-z0-9-]+)\/[A-Za-z0-9.-]+$/.test(servicePrincipal)) {
      throw new TypeError("Invalid service principal format.");
    }

    // The TGS exchange uses the TGT to obtain a service-specific ticket.
    return this.#issue(
      tgt.clientPrincipal,
      servicePrincipal,
      "SERVICE",
      Math.min(tgt.expiresAt, Date.now() + this.ticketLifetimeMs),
    );
  }

  validateServiceTicket(ticketId, expectedService) {
    const ticket = this.tickets.get(ticketId);
    if (!ticket || ticket.kind !== "SERVICE") {
      throw new AuthenticationError("Service ticket required.");
    }
    if (Date.now() >= ticket.expiresAt) {
      throw new AuthenticationError("Service ticket expired.");
    }
    if (ticket.servicePrincipal !== expectedService) {
      throw new AuthenticationError("Wrong service principal.");
    }

    const [qualifiedUser, domain] = ticket.clientPrincipal.split("@");
    const username = qualifiedUser.split("\\").at(-1);
    const account = this.store.get(username, domain);

    if (!account.enabled || account.locked) {
      throw new AuthenticationError("Account is unavailable.");
    }

    this.audit.record(
      "kerberos-service",
      ticket.clientPrincipal,
      "success",
      `Ticket accepted for ${expectedService}`,
    );
    return SessionFactory.create(account, Protocol.KERBEROS, "network");
  }

  #issue(clientPrincipal, servicePrincipal, kind, expiry = null) {
    const now = Date.now();
    const ticket = Object.freeze({
      id: crypto.randomUUID(),
      clientPrincipal,
      servicePrincipal,
      kind,
      issuedAt: now,
      expiresAt: expiry ?? now + this.ticketLifetimeMs,
      sessionKey: crypto.randomBytes(32),
    });
    this.tickets.set(ticket.id, ticket);

    this.audit.record(
      kind === "TGT" ? "kerberos-as" : "kerberos-tgs",
      clientPrincipal,
      "success",
      `Synthetic ${kind} issued`,
    );
    return ticket;
  }
}

class ResourceAuthorizationService {
  constructor() {
    this.groupPermissions = new Map();
  }

  grant(group, resource) {
    if (!this.groupPermissions.has(group)) {
      this.groupPermissions.set(group, new Set());
    }
    this.groupPermissions.get(group).add(resource);
  }

  authorize(session, resource) {
    if (!session || !session.principal) {
      throw new AuthorizationError("Authenticated session required.");
    }

    const permitted = session.groups.some(
      (group) => this.groupPermissions.get(group)?.has(resource),
    );
    if (!permitted) {
      throw new AuthorizationError(
        `${session.principal} is not authorized for ${resource}`,
      );
    }
    return true;
  }
}

async function main() {
  const audit = new AuditTrail();
  audit.on("authentication", (event) => {
    console.log(
      `[AUDIT] ${event.type}: ${event.principal} -> ${event.outcome}`,
    );
  });

  const store = new AccountStore();

  await store.create({
    username: "helpdesk",
    password: "LocalPass!2026",
    kind: AccountKind.LOCAL,
    groups: ["Users", "IT Support"],
  });

  await store.create({
    username: "alex",
    password: "DomainPass!2026",
    kind: AccountKind.DOMAIN,
    domain: "CORP.EXAMPLE",
    groups: ["Domain Users"],
  });

  console.log("\n=== Local logon ===");
  const localSession = await new LocalLogonService(store, audit)
    .authenticate("helpdesk", "LocalPass!2026");
  console.log(localSession);

  console.log("\n=== NTLM concept ===");
  const ntlm = new NtlmExchange(store, audit);
  const challenge = ntlm.issueChallenge("fileserver.corp.example");
  const response = NtlmExchange.makeResponse(
    "DomainPass!2026",
    challenge,
    "alex",
    "CORP.EXAMPLE",
  );

  const ntlmSession = await ntlm.authenticate({
    username: "alex",
    domain: "CORP.EXAMPLE",
    password: "DomainPass!2026",
    challengeId: challenge.id,
    response,
  });
  console.log(ntlmSession);

  console.log("\n=== Kerberos concept ===");
  const kdc = new KerberosTicketAuthority(store, audit);
  const tgt = await kdc.authenticateInitialCredentials(
    "alex",
    "CORP.EXAMPLE",
    "DomainPass!2026",
  );
  console.log("TGT obtained.");

  const serviceTicket = kdc.requestServiceTicket(
    tgt.id,
    "HTTP/intranet.corp.example",
  );
  const kerberosSession = kdc.validateServiceTicket(
    serviceTicket.id,
    "HTTP/intranet.corp.example",
  );
  console.log(kerberosSession);

  console.log("\n=== Resource authorization ===");
  const access = new ResourceAuthorizationService();
  access.grant("Domain Users", "intranet.read");
  access.grant("IT Support", "password-reset");

  for (const [session, resource] of [
    [localSession, "password-reset"],
    [kerberosSession, "intranet.read"],
    [kerberosSession, "payroll.admin"],
  ]) {
    try {
      access.authorize(session, resource);
      console.log("GRANTED", session.principal, resource);
    } catch (error) {
      console.log("DENIED", session.principal, resource, error.message);
    }
  }

  console.log(`\nRecorded audit events: ${audit.events.length}`);
  console.log(
    "Security boundary: this is a synthetic model, not a Windows protocol client.",
  );
}

main().catch((error) => {
  console.error("Workflow failed:", error.message);
  process.exitCode = 1;
});
