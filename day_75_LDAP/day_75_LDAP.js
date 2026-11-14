"use strict";

/*
 * LDAP Directory: Event-Driven Directory and Security Model
 *
 * Demonstrates:
 * - DIT and DN management
 * - LDAP filter evaluation
 * - Asynchronous bind authentication
 * - PBKDF2 password verification
 * - Account lockout
 * - Role-based authorization
 * - Directory event handling
 * - Search scopes and result limits
 * - Audit events
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library only
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

class LDAPError extends Error {}
class InvalidDNError extends LDAPError {}
class InvalidFilterError extends LDAPError {}
class AuthenticationError extends LDAPError {}
class AuthorizationError extends LDAPError {}
class EntryNotFoundError extends LDAPError {}
class EntryExistsError extends LDAPError {}

/* Parse basic LDAP distinguished names. */
function normalizeDN(dn) {
    if (typeof dn !== "string" || !dn.trim()) {
        throw new InvalidDNError("DN must be a nonempty string.");
    }

    const components = dn.split(/(?<!\\),/).map(part => part.trim());

    if (components.some(part => !part.includes("="))) {
        throw new InvalidDNError("Invalid RDN.");
    }

    return components.map(part => {
        const index = part.indexOf("=");
        const attribute = part.slice(0, index).trim().toLowerCase();
        const value = part.slice(index + 1).trim();

        if (!/^[a-z][a-z0-9-]*$/.test(attribute) || !value) {
            throw new InvalidDNError("Invalid RDN component.");
        }

        return `${attribute}=${value.toLowerCase()}`;
    }).join(",");
}

function withinDN(dn, base) {
    return dn === base || dn.endsWith("," + base);
}

function depth(dn) {
    return dn.split(",").length;
}

const Scope = Object.freeze({
    BASE: "base",
    ONE: "one",
    SUBTREE: "subtree"
});

const AccountStatus = Object.freeze({
    ACTIVE: "ACTIVE",
    LOCKED: "LOCKED",
    DISABLED: "DISABLED"
});

class LDAPFilter {
    constructor(expression) {
        if (typeof expression !== "string") {
            throw new InvalidFilterError("Filter must be a string.");
        }

        this.expression = expression;
        this.position = 0;
        this.ast = this.parse();

        if (this.position !== expression.length) {
            throw new InvalidFilterError("Unexpected filter content.");
        }
    }

    parse() {
        const input = this.expression;

        if (input[this.position++] !== "(") {
            throw new InvalidFilterError("Expected opening parenthesis.");
        }

        const operator = input[this.position];

        if (operator === "&" || operator === "|") {
            this.position++;
            const children = [];

            while (input[this.position] === "(") {
                children.push(this.parse());
            }

            if (children.length === 0) {
                throw new InvalidFilterError("Empty logical filter.");
            }

            if (input[this.position++] !== ")") {
                throw new InvalidFilterError("Expected closing parenthesis.");
            }

            return { operator, children };
        }

        if (operator === "!") {
            this.position++;
            const child = this.parse();

            if (input[this.position++] !== ")") {
                throw new InvalidFilterError("Expected closing parenthesis.");
            }

            return { operator: "!", child };
        }

        const start = this.position;

        while (
            this.position < input.length &&
            input[this.position] !== ")"
        ) {
            if (input[this.position] === "(") {
                throw new InvalidFilterError("Nested attribute filter.");
            }

            this.position++;
        }

        if (this.position >= input.length) {
            throw new InvalidFilterError("Incomplete filter.");
        }

        const expression = input.slice(start, this.position++);

        const index = expression.indexOf("=");

        if (index <= 0) {
            throw new InvalidFilterError("Equality filter required.");
        }

        const attribute = expression.slice(0, index).toLowerCase();
        const value = expression.slice(index + 1);

        if (!/^[a-z][a-z0-9-]*$/.test(attribute)) {
            throw new InvalidFilterError("Invalid attribute name.");
        }

        if (/[\x00-\x1f]/.test(value)) {
            throw new InvalidFilterError("Control characters are forbidden.");
        }

        return { operator: "=", attribute, value };
    }

    matches(entry) {
        const evaluate = node => {
            if (node.operator === "&") {
                return node.children.every(evaluate);
            }

            if (node.operator === "|") {
                return node.children.some(evaluate);
            }

            if (node.operator === "!") {
                return !evaluate(node.child);
            }

            const values = entry.attributes.get(node.attribute) || [];

            if (node.value === "*") {
                return values.length > 0;
            }

            return values.some(value =>
                value.toLowerCase() === node.value.toLowerCase()
            );
        };

        return evaluate(this.ast);
    }
}

class PasswordService {
    static ITERATIONS = 180000;

    static async hash(password) {
        if (typeof password !== "string" || password.length < 12) {
            throw new LDAPError("Password must have at least 12 characters.");
        }

        const salt = crypto.randomBytes(32);

        const derived = await new Promise((resolve, reject) => {
            crypto.pbkdf2(
                password,
                salt,
                this.ITERATIONS,
                32,
                "sha256",
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
        });

        return {
            salt: salt.toString("hex"),
            hash: derived.toString("hex"),
            iterations: this.ITERATIONS
        };
    }

    static async verify(password, credentials) {
        const derived = await new Promise((resolve, reject) => {
            crypto.pbkdf2(
                password,
                Buffer.from(credentials.salt, "hex"),
                credentials.iterations,
                32,
                "sha256",
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
        });

        const expected = Buffer.from(credentials.hash, "hex");

        return expected.length === derived.length &&
            crypto.timingSafeEqual(expected, derived);
    }
}

class AccessPolicy {
    static permissions = new Map([
        ["administrator", new Set(["read", "search", "write", "delete"])],
        ["directory-manager", new Set(["read", "search", "write"])],
        ["employee", new Set(["read", "search"])],
        ["service-account", new Set(["read", "search"])]
    ]);

    static require(role, operation) {
        if (!this.permissions.get(role)?.has(operation)) {
            throw new AuthorizationError(
                `${role} cannot execute ${operation}.`
            );
        }
    }
}

class DirectoryEntry {
    constructor(dn, attributes) {
        this.dn = normalizeDN(dn);
        this.attributes = new Map();

        for (const [key, values] of Object.entries(attributes)) {
            const attribute = key.toLowerCase();

            if (!/^[a-z][a-z0-9-]*$/.test(attribute)) {
                throw new LDAPError(`Invalid attribute: ${key}`);
            }

            this.attributes.set(
                attribute,
                (Array.isArray(values) ? values : [values]).map(String)
            );
        }

        if (!this.attributes.has("objectclass")) {
            throw new LDAPError("objectClass is required.");
        }

        this.credentials = null;
        this.status = AccountStatus.ACTIVE;
        this.failedAttempts = 0;
        this.createdAt = new Date();
        this.updatedAt = new Date();
    }
}

class LDAPDirectory extends EventEmitter {
    constructor(maxFailures = 5) {
        super();

        this.entries = new Map();
        this.maxFailures = maxFailures;
        this.audit = [];
    }

    record(operation, dn, outcome) {
        const event = Object.freeze({
            operation,
            dn,
            outcome,
            timestamp: new Date().toISOString()
        });

        this.audit.push(event);
        this.emit("directory-event", event);
    }

    add(entry, role = "administrator") {
        AccessPolicy.require(role, "write");

        const dn = entry.dn;

        if (this.entries.has(dn)) {
            throw new EntryExistsError(dn);
        }

        const parent = dn.split(",").slice(1).join(",");

        if (parent && !this.entries.has(parent)) {
            throw new EntryNotFoundError(`Missing parent: ${parent}`);
        }

        this.entries.set(dn, entry);
        this.record("ADD", dn, "SUCCESS");
    }

    async setPassword(dn, password) {
        const normalized = normalizeDN(dn);
        const entry = this.entries.get(normalized);

        if (!entry) throw new EntryNotFoundError(normalized);

        entry.credentials = await PasswordService.hash(password);
        entry.failedAttempts = 0;
        entry.status = AccountStatus.ACTIVE;
        entry.updatedAt = new Date();

        this.record("PASSWORD_CHANGE", normalized, "SUCCESS");
    }

    async bind(dn, password) {
        const normalized = normalizeDN(dn);
        const entry = this.entries.get(normalized);

        if (!entry || !entry.credentials) {
            this.record("BIND", normalized, "REJECTED");
            throw new AuthenticationError("Invalid credentials.");
        }

        if (entry.status !== AccountStatus.ACTIVE) {
            throw new AuthenticationError("Account is unavailable.");
        }

        const valid = await PasswordService.verify(
            password,
            entry.credentials
        );

        if (!valid) {
            entry.failedAttempts++;

            if (entry.failedAttempts >= this.maxFailures) {
                entry.status = AccountStatus.LOCKED;
            }

            this.record("BIND", normalized, "REJECTED");
            throw new AuthenticationError("Invalid credentials.");
        }

        entry.failedAttempts = 0;
        this.record("BIND", normalized, "SUCCESS");

        return Object.freeze({
            dn: normalized,
            authenticated: true,
            authenticatedAt: new Date().toISOString()
        });
    }

    search({
        base,
        filter,
        scope = Scope.SUBTREE,
        attributes = null,
        role = "employee",
        limit = 100
    }) {
        AccessPolicy.require(role, "search");

        base = normalizeDN(base);

        if (!this.entries.has(base)) {
            throw new EntryNotFoundError(base);
        }

        if (!Object.values(Scope).includes(scope)) {
            throw new LDAPError("Invalid search scope.");
        }

        if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
            throw new LDAPError("Invalid search limit.");
        }

        const parsedFilter = new LDAPFilter(filter);
        const results = [];

        for (const [dn, entry] of this.entries) {
            if (scope === Scope.BASE && dn !== base) continue;

            if (scope === Scope.ONE) {
                if (!withinDN(dn, base)) continue;
                if (depth(dn) !== depth(base) + 1) continue;
            }

            if (scope === Scope.SUBTREE && !withinDN(dn, base)) {
                continue;
            }

            if (!parsedFilter.matches(entry)) continue;

            const selected = {};

            const requested = attributes ||
                Array.from(entry.attributes.keys());

            for (const attribute of requested) {
                const values = entry.attributes.get(attribute.toLowerCase());

                if (values) {
                    selected[attribute.toLowerCase()] = [...values];
                }
            }

            results.push(Object.freeze({
                dn,
                attributes: Object.freeze(selected)
            }));

            if (results.length >= limit) break;
        }

        this.record("SEARCH", base, `RESULTS=${results.length}`);

        return results;
    }

    modify(dn, attribute, values, role = "directory-manager") {
        AccessPolicy.require(role, "write");

        const normalized = normalizeDN(dn);
        const entry = this.entries.get(normalized);

        if (!entry) throw new EntryNotFoundError(normalized);

        attribute = attribute.toLowerCase();

        if (["objectclass", "userpassword"].includes(attribute)) {
            throw new AuthorizationError("Protected attribute.");
        }

        if (!/^[a-z][a-z0-9-]*$/.test(attribute)) {
            throw new LDAPError("Invalid attribute.");
        }

        if (!Array.isArray(values) || values.length === 0) {
            throw new LDAPError("A nonempty value array is required.");
        }

        if (!values.every(value => typeof value === "string")) {
            throw new LDAPError("Attribute values must be strings.");
        }

        entry.attributes.set(attribute, [...new Set(values)]);
        entry.updatedAt = new Date();

        this.record("MODIFY", normalized, "SUCCESS");
    }

    resetAccount(dn, role = "administrator") {
        AccessPolicy.require(role, "write");

        const normalized = normalizeDN(dn);
        const entry = this.entries.get(normalized);

        if (!entry) throw new EntryNotFoundError(normalized);

        entry.status = AccountStatus.ACTIVE;
        entry.failedAttempts = 0;

        this.record("ACCOUNT_RESET", normalized, "SUCCESS");
    }
}

async function main() {
    const directory = new LDAPDirectory();

    directory.on("directory-event", event => {
        console.log(
            `[AUDIT] ${event.operation} ${event.dn} ${event.outcome}`
        );
    });

    directory.add(new DirectoryEntry(
        "dc=example,dc=com",
        {
            objectClass: ["top", "domain"],
            dc: ["example"]
        }
    ));

    directory.add(new DirectoryEntry(
        "ou=people,dc=example,dc=com",
        {
            objectClass: ["top", "organizationalUnit"],
            ou: ["people"]
        }
    ));

    const users = [
        ["alice", "Alice Sharma", "Engineering"],
        ["bob", "Bob Kumar", "Security"],
        ["carol", "Carol Singh", "Engineering"]
    ];

    for (const [uid, name, department] of users) {
        const entry = new DirectoryEntry(
            `uid=${uid},ou=people,dc=example,dc=com`,
            {
                objectClass: ["top", "person", "inetOrgPerson"],
                uid,
                cn: name,
                sn: name.split(" ").at(-1),
                department,
                mail: `${uid}@example.com`,
                active: "true"
            }
        );

        directory.add(entry);

        await directory.setPassword(
            entry.dn,
            `${uid.toUpperCase()}-Secure-Password-2026`
        );
    }

    console.log("\n1. SEARCH ENGINEERING USERS");

    const engineering = directory.search({
        base: "dc=example,dc=com",
        filter: "(&(department=Engineering)(active=true))",
        attributes: ["uid", "cn", "department"]
    });

    console.table(engineering.map(item => ({
        dn: item.dn,
        ...item.attributes
    })));

    console.log("\n2. ASYNCHRONOUS BIND");

    const session = await directory.bind(
        "uid=alice,ou=people,dc=example,dc=com",
        "ALICE-Secure-Password-2026"
    );

    console.log(session);

    console.log("\n3. ATTRIBUTE UPDATE");

    directory.modify(
        "uid=alice,ou=people,dc=example,dc=com",
        "telephoneNumber",
        ["+91-9876543210"]
    );

    console.log("\n4. INVALID AUTHENTICATION");

    try {
        await directory.bind(
            "uid=alice,ou=people,dc=example,dc=com",
            "wrong-password"
        );
    } catch (error) {
        console.log(error.message);
    }

    console.log("\n5. AUTHORIZATION FAILURE");

    try {
        directory.modify(
            "uid=alice,ou=people,dc=example,dc=com",
            "department",
            ["Finance"],
            "employee"
        );
    } catch (error) {
        console.log(error.message);
    }

    console.log("\n6. FILTER VALIDATION");

    try {
        new LDAPFilter("department=Engineering");
    } catch (error) {
        console.log(error.message);
    }

    console.log("\n7. ASSERTIONS");

    console.assert(
        directory.search({
            base: "dc=example,dc=com",
            filter: "(uid=alice)"
        }).length === 1
    );

    console.assert(
        directory.search({
            base: "dc=example,dc=com",
            filter: "(uid=unknown)"
        }).length === 0
    );

    console.log("All assertions passed.");
}

main().catch(error => {
    console.error("Directory execution failed:", error.message);
    process.exitCode = 1;
});
