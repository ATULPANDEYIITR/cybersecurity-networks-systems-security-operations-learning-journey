'use strict';

/*
 * Active Directory Security Governance Engine
 *
 * Node.js 18+
 *
 * Focus:
 * - Event-driven account governance
 * - Privileged identity policies
 * - Delegation evaluation
 * - Service account lifecycle
 * - Trust security
 * - Attack-path relationship analysis
 * - Risk scoring and remediation events
 *
 * Uses only Node.js built-in modules.
 */

const fs = require('node:fs/promises');
const { EventEmitter } = require('node:events');

const AccountType = Object.freeze({
    USER: 'user',
    ADMIN: 'administrator',
    SERVICE: 'service',
    MANAGED_SERVICE: 'managed_service'
});

const Tier = Object.freeze({
    TIER_0: 0,
    TIER_1: 1,
    TIER_2: 2
});

const Delegation = Object.freeze({
    NONE: 'none',
    UNCONSTRAINED: 'unconstrained',
    CONSTRAINED: 'constrained',
    RESOURCE_BASED: 'resource_based'
});

const Severity = Object.freeze({
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low'
});

const Status = Object.freeze({
    OPEN: 'open',
    MITIGATED: 'mitigated',
    ACCEPTED: 'accepted'
});

class SecurityError extends Error {}

class ValidationError extends SecurityError {}

class PolicyViolation extends SecurityError {}

function validateAccount(account) {
    if (!account || typeof account !== 'object') {
        throw new ValidationError('Account must be an object');
    }

    if (
        typeof account.name !== 'string' ||
        !/^[A-Za-z0-9_.-]{1,64}$/.test(account.name)
    ) {
        throw new ValidationError('Invalid account name');
    }

    if (!Object.values(AccountType).includes(account.type)) {
        throw new ValidationError('Invalid account type');
    }

    if (!Object.values(Tier).includes(account.tier)) {
        throw new ValidationError('Invalid security tier');
    }

    if (
        !Number.isInteger(account.passwordAgeDays) ||
        account.passwordAgeDays < 0
    ) {
        throw new ValidationError('Invalid password age');
    }

    if (
        !Number.isInteger(account.spnCount) ||
        account.spnCount < 0
    ) {
        throw new ValidationError('Invalid SPN count');
    }
}

class SecurityPolicy {
    constructor({
        requirePrivilegedMFA = true,
        maximumServicePasswordAge = 180,
        prohibitUnconstrainedDelegation = true,
        requireManagedServicePasswords = true,
        requireTrustSIDFiltering = true,
        requireSelectiveAuthentication = true
    } = {}) {
        this.requirePrivilegedMFA = requirePrivilegedMFA;
        this.maximumServicePasswordAge = maximumServicePasswordAge;
        this.prohibitUnconstrainedDelegation =
            prohibitUnconstrainedDelegation;
        this.requireManagedServicePasswords =
            requireManagedServicePasswords;
        this.requireTrustSIDFiltering = requireTrustSIDFiltering;
        this.requireSelectiveAuthentication =
            requireSelectiveAuthentication;

        Object.freeze(this);
    }

    evaluateAccount(account) {
        const findings = [];

        if (!account.enabled) {
            return findings;
        }

        if (
            this.requirePrivilegedMFA &&
            account.privileged &&
            !account.mfaEnabled
        ) {
            findings.push({
                severity: Severity.CRITICAL,
                category: 'PRIVILEGED_MFA',
                subject: account.name,
                message: 'Privileged account lacks MFA.'
            });
        }

        if (
            account.privileged &&
            account.passwordNeverExpires
        ) {
            findings.push({
                severity: Severity.HIGH,
                category: 'PASSWORD_LIFECYCLE',
                subject: account.name,
                message: 'Privileged account has a non-expiring password.'
            });
        }

        if (
            account.type === AccountType.ADMIN &&
            account.privileged &&
            account.tier !== Tier.TIER_0 &&
            account.interactiveLogonAllowed
        ) {
            findings.push({
                severity: Severity.HIGH,
                category: 'TIER_VIOLATION',
                subject: account.name,
                message: 'Review administrative tier and logon scope.'
            });
        }

        if (
            this.prohibitUnconstrainedDelegation &&
            account.delegation === Delegation.UNCONSTRAINED
        ) {
            findings.push({
                severity: Severity.CRITICAL,
                category: 'KERBEROS_DELEGATION',
                subject: account.name,
                message: 'Unconstrained delegation is configured.'
            });
        }

        if (
            account.trustedToAuthenticate
        ) {
            findings.push({
                severity: Severity.HIGH,
                category: 'PROTOCOL_TRANSITION',
                subject: account.name,
                message: 'Protocol transition requires review.'
            });
        }

        if (
            account.type === AccountType.SERVICE &&
            this.requireManagedServicePasswords &&
            !account.managedPassword
        ) {
            findings.push({
                severity: Severity.HIGH,
                category: 'SERVICE_CREDENTIALS',
                subject: account.name,
                message: 'Service account does not use managed credentials.'
            });
        }

        if (
            account.type === AccountType.SERVICE &&
            account.spnCount > 0 &&
            account.passwordAgeDays >
                this.maximumServicePasswordAge
        ) {
            findings.push({
                severity: Severity.HIGH,
                category: 'SERVICE_PASSWORD_AGE',
                subject: account.name,
                message: 'SPN-bearing account has an old password.'
            });
        }

        if (
            [AccountType.SERVICE, AccountType.MANAGED_SERVICE]
                .includes(account.type) &&
            account.interactiveLogonAllowed
        ) {
            findings.push({
                severity: Severity.MEDIUM,
                category: 'INTERACTIVE_SERVICE_LOGON',
                subject: account.name,
                message: 'Service identity permits interactive logon.'
            });
        }

        return findings;
    }

    evaluateTrust(trust) {
        const findings = [];

        if (!trust.enabled) {
            return findings;
        }

        if (
            this.requireTrustSIDFiltering &&
            !trust.sidFiltering
        ) {
            findings.push({
                severity: Severity.CRITICAL,
                category: 'TRUST_SID_FILTERING',
                subject: trust.id,
                message: 'SID filtering is not enforced.'
            });
        }

        if (
            this.requireSelectiveAuthentication &&
            !trust.selectiveAuthentication
        ) {
            findings.push({
                severity: Severity.HIGH,
                category: 'TRUST_AUTHENTICATION',
                subject: trust.id,
                message: 'Selective authentication is disabled.'
            });
        }

        return findings;
    }
}

class DirectorySecurityEngine extends EventEmitter {
    constructor(domain, policy = new SecurityPolicy()) {
        super();

        if (
            typeof domain !== 'string' ||
            !/^(?=.{1,253}$)[a-z0-9.-]+$/i.test(domain)
        ) {
            throw new ValidationError('Invalid domain');
        }

        this.domain = domain.toLowerCase();
        this.policy = policy;

        this.accounts = new Map();
        this.trusts = new Map();
        this.relationships = new Map();
        this.findings = new Map();

        this.nextFindingId = 1;

        this.on('finding.created', finding => {
            this.findings.set(finding.id, finding);
        });

        this.on('finding.updated', finding => {
            if (!this.findings.has(finding.id)) {
                throw new ValidationError('Unknown finding');
            }

            this.findings.set(finding.id, finding);
        });
    }

    addAccount(account) {
        validateAccount(account);

        const key = account.name.toLowerCase();

        if (this.accounts.has(key)) {
            throw new ValidationError('Duplicate account');
        }

        this.accounts.set(key, Object.freeze({ ...account }));
        this.emit('account.created', account);
    }

    addTrust(trust) {
        if (
            !trust ||
            typeof trust.id !== 'string' ||
            !trust.id.trim() ||
            typeof trust.targetDomain !== 'string' ||
            !trust.targetDomain.trim()
        ) {
            throw new ValidationError('Invalid trust');
        }

        if (trust.targetDomain.toLowerCase() === this.domain) {
            throw new ValidationError('Self-trust is invalid');
        }

        if (this.trusts.has(trust.id)) {
            throw new ValidationError('Duplicate trust');
        }

        this.trusts.set(
            trust.id,
            Object.freeze({ ...trust })
        );
    }

    addRelationship(source, target, permission) {
        if (!source || !target || source === target) {
            throw new ValidationError('Invalid relationship');
        }

        if (typeof permission !== 'string' || !permission.trim()) {
            throw new ValidationError('Invalid permission');
        }

        const key = `${source}:${target}:${permission}`;

        if (!this.relationships.has(source)) {
            this.relationships.set(source, new Map());
        }

        const outgoing = this.relationships.get(source);

        if (!outgoing.has(key)) {
            outgoing.set(key, {
                source,
                target,
                permission
            });
        }
    }

    createFinding(data) {
        const finding = Object.freeze({
            id: `AD-${String(this.nextFindingId++).padStart(4, '0')}`,
            ...data,
            status: Status.OPEN,
            createdAt: new Date().toISOString()
        });

        this.emit('finding.created', finding);
    }

    auditAccounts() {
        for (const account of this.accounts.values()) {
            const results = this.policy.evaluateAccount(account);

            for (const result of results) {
                this.createFinding(result);
            }
        }
    }

    auditTrusts() {
        for (const trust of this.trusts.values()) {
            const results = this.policy.evaluateTrust(trust);

            for (const result of results) {
                this.createFinding(result);
            }
        }
    }

    audit() {
        this.findings.clear();
        this.nextFindingId = 1;

        this.auditAccounts();
        this.auditTrusts();

        this.emit('audit.completed', {
            domain: this.domain,
            findingCount: this.findings.size
        });

        return this.getReport();
    }

    resolveFinding(id, status) {
        if (!Object.values(Status).includes(status)) {
            throw new ValidationError('Invalid finding status');
        }

        const existing = this.findings.get(id);

        if (!existing) {
            throw new ValidationError('Finding not found');
        }

        const updated = Object.freeze({
            ...existing,
            status,
            updatedAt: new Date().toISOString()
        });

        this.emit('finding.updated', updated);
        return updated;
    }

    shortestPaths(start, target, maximumDepth = 8) {
        if (
            !Number.isInteger(maximumDepth) ||
            maximumDepth < 1
        ) {
            throw new ValidationError('Invalid maximum depth');
        }

        if (start === target) {
            return [[start]];
        }

        const queue = [[start, [start]]];
        const bestDepth = new Map([[start, 0]]);
        const results = [];
        let shortest = Infinity;

        while (queue.length > 0) {
            const [node, path] = queue.shift();
            const depth = path.length - 1;

            if (depth >= maximumDepth || depth >= shortest) {
                continue;
            }

            const edges = this.relationships.get(node);

            if (!edges) {
                continue;
            }

            for (const edge of edges.values()) {
                if (path.includes(edge.target)) {
                    continue;
                }

                const nextPath = [...path, edge.target];
                const nextDepth = depth + 1;

                if (edge.target === target) {
                    shortest = nextDepth;
                    results.push(nextPath);
                    continue;
                }

                if (nextDepth <= (bestDepth.get(edge.target) ?? Infinity)) {
                    bestDepth.set(edge.target, nextDepth);
                    queue.push([edge.target, nextPath]);
                }
            }
        }

        return results.filter(path => path.length - 1 === shortest);
    }

    getReport() {
        const counts = Object.fromEntries(
            Object.values(Severity).map(severity => [
                severity,
                [...this.findings.values()]
                    .filter(f => f.severity === severity).length
            ])
        );

        return {
            domain: this.domain,
            accounts: this.accounts.size,
            trusts: this.trusts.size,
            findings: [...this.findings.values()],
            severityCounts: counts
        };
    }

    async exportReport(filename) {
        if (
            typeof filename !== 'string' ||
            !/^[A-Za-z0-9_-]+\.json$/.test(filename)
        ) {
            throw new ValidationError('Invalid report filename');
        }

        const content = JSON.stringify(this.getReport(), null, 2);

        await fs.writeFile(filename, content, {
            encoding: 'utf8',
            flag: 'w',
            mode: 0o600
        });
    }
}

async function main() {
    const engine = new DirectorySecurityEngine(
        'corp.example.com'
    );

    engine.on('audit.completed', event => {
        console.log(
            `Audit completed: ${event.findingCount} findings`
        );
    });

    engine.on('finding.created', finding => {
        console.log(
            `[${finding.severity.toUpperCase()}] ` +
            `${finding.category}: ${finding.subject}`
        );
    });

    engine.on('finding.updated', finding => {
        console.log(
            `${finding.id} updated: ${finding.status}`
        );
    });

    engine.addAccount({
        name: 'domain_admin',
        type: AccountType.ADMIN,
        tier: Tier.TIER_0,
        enabled: true,
        privileged: true,
        mfaEnabled: true,
        passwordNeverExpires: false,
        interactiveLogonAllowed: false,
        delegation: Delegation.NONE,
        trustedToAuthenticate: false,
        managedPassword: false,
        spnCount: 0,
        passwordAgeDays: 30
    });

    engine.addAccount({
        name: 'helpdesk_admin',
        type: AccountType.ADMIN,
        tier: Tier.TIER_2,
        enabled: true,
        privileged: true,
        mfaEnabled: false,
        passwordNeverExpires: true,
        interactiveLogonAllowed: true,
        delegation: Delegation.NONE,
        trustedToAuthenticate: false,
        managedPassword: false,
        spnCount: 0,
        passwordAgeDays: 120
    });

    engine.addAccount({
        name: 'sql_service',
        type: AccountType.SERVICE,
        tier: Tier.TIER_1,
        enabled: true,
        privileged: false,
        mfaEnabled: false,
        passwordNeverExpires: true,
        interactiveLogonAllowed: true,
        delegation: Delegation.NONE,
        trustedToAuthenticate: false,
        managedPassword: false,
        spnCount: 2,
        passwordAgeDays: 240
    });

    engine.addAccount({
        name: 'legacy_web',
        type: AccountType.SERVICE,
        tier: Tier.TIER_1,
        enabled: true,
        privileged: false,
        mfaEnabled: false,
        passwordNeverExpires: true,
        interactiveLogonAllowed: true,
        delegation: Delegation.UNCONSTRAINED,
        trustedToAuthenticate: true,
        managedPassword: false,
        spnCount: 1,
        passwordAgeDays: 300
    });

    engine.addAccount({
        name: 'web_gmsa',
        type: AccountType.MANAGED_SERVICE,
        tier: Tier.TIER_1,
        enabled: true,
        privileged: false,
        mfaEnabled: false,
        passwordNeverExpires: false,
        interactiveLogonAllowed: false,
        delegation: Delegation.NONE,
        trustedToAuthenticate: false,
        managedPassword: true,
        spnCount: 1,
        passwordAgeDays: 5
    });

    engine.addTrust({
        id: 'TRUST-001',
        targetDomain: 'partner.example.net',
        enabled: true,
        sidFiltering: false,
        selectiveAuthentication: false
    });

    engine.addRelationship(
        'employee01',
        'helpdesk_admin',
        'group_membership'
    );

    engine.addRelationship(
        'helpdesk_admin',
        'server01',
        'administrative_access'
    );

    engine.addRelationship(
        'server01',
        'legacy_web',
        'service_dependency'
    );

    engine.addRelationship(
        'legacy_web',
        'domain_admin',
        'delegation_exposure'
    );

    const report = engine.audit();

    console.log('\nRISK DISTRIBUTION');
    console.table(report.severityCounts);

    console.log('\nDEFENSIVE RELATIONSHIP ANALYSIS');

    const paths = engine.shortestPaths(
        'employee01',
        'domain_admin'
    );

    console.log(paths);

    const firstFinding = report.findings[0];

    if (firstFinding) {
        engine.resolveFinding(
            firstFinding.id,
            Status.MITIGATED
        );
    }

    await engine.exportReport('ad_security_report.json');
}

main().catch(error => {
    console.error('Security engine failure:', error.message);
    process.exitCode = 1;
});
