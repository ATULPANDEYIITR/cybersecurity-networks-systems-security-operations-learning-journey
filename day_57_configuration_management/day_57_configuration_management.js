'use strict';

/*
 * Secure Configuration Management
 *
 * Event-driven model for baselines, configuration drift, compliance,
 * approval-controlled remediation, and protected secret handling.
 */

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const fs = require('node:fs/promises');

class ConfigurationError extends Error {}

const SECRET_KEY = /(password|passwd|secret|token|api[-_]?key|private[-_]?key)/i;

class ConfigItem {
    constructor(key, value, { required = true, secret = false } = {}) {
        if (!/^[A-Za-z0-9_.-]+$/.test(key)) {
            throw new ConfigurationError(`Invalid configuration key: ${key}`);
        }
        this.key = key;
        this.value = value;
        this.required = required;
        this.secret = secret;
    }
}

class Baseline {
    constructor(name, version, items) {
        if (!name || version < 1 || !items?.size) {
            throw new ConfigurationError('Invalid baseline definition');
        }
        this.name = name;
        this.version = version;
        this.items = items;
        this.checksum = this.computeChecksum();
    }

    computeChecksum() {
        const canonical = [...this.items.entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, item]) => ({
                key,
                value: item.secret ? '<SECRET>' : item.value,
                required: item.required,
                secret: item.secret
            }));
        return crypto
            .createHash('sha256')
            .update(JSON.stringify({
                name: this.name,
                version: this.version,
                items: canonical
            }))
            .digest('hex');
    }

    verifyIntegrity() {
        return this.checksum === this.computeChecksum();
    }
}

class ConfigurationService extends EventEmitter {
    constructor(baseline) {
        super();
        this.baseline = baseline;
        this.current = new Map();
        this.state = 'PROPOSED';
        this.audit = [];
    }

    record(action, actor, target, details) {
        const event = Object.freeze({
            action,
            actor,
            target,
            details,
            timestamp: new Date().toISOString()
        });
        this.audit.push(event);
        this.emit('audit', event);
    }

    load(configuration) {
        if (!configuration || typeof configuration !== 'object') {
            throw new ConfigurationError('Configuration must be an object');
        }
        this.current = new Map(Object.entries(configuration));
        this.record('CONFIG_LOADED', 'system', this.baseline.name, 'Current state loaded');
    }

    detectDrift() {
        if (!this.baseline.verifyIntegrity()) {
            throw new ConfigurationError('Baseline integrity failure');
        }

        const drift = [];

        for (const [key, item] of this.baseline.items) {
            if (!this.current.has(key)) {
                if (item.required) {
                    drift.push({ key, reason: 'required key missing' });
                }
                continue;
            }

            const actual = this.current.get(key);
            if (item.secret) {
                if (actual !== item.value) {
                    drift.push({ key, reason: 'secret value differs' });
                }
            } else if (actual !== item.value) {
                drift.push({
                    key,
                    expected: item.value,
                    actual,
                    reason: 'value differs'
                });
            }
        }

        for (const key of this.current.keys()) {
            if (!this.baseline.items.has(key)) {
                drift.push({ key, reason: 'unauthorized key present' });
            }
        }

        return drift;
    }

    evaluatePolicies(policies) {
        const violations = [];
        for (const policy of policies) {
            const value = this.current.get(policy.key);
            let valid = false;
            try {
                valid = policy.check(value);
            } catch (error) {
                violations.push(`${policy.name}: evaluation failure`);
                continue;
            }
            if (!valid) {
                violations.push(`${policy.name}: ${policy.severity}`);
            }
        }
        return violations;
    }

    async propose(actor, key, value) {
        if (!actor || !this.baseline.items.has(key)) {
            throw new ConfigurationError('Actor or approved key is invalid');
        }

        const item = this.baseline.items.get(key);
        if (item.secret && typeof value !== 'string') {
            throw new ConfigurationError('Secret values must be strings');
        }

        this.current.set(key, value);
        this.state = 'PROPOSED';
        this.record('CHANGE_PROPOSED', actor, key, 'Configuration change proposed');

        await Promise.resolve();
    }

    approve(actor) {
        if (this.state !== 'PROPOSED') {
            throw new ConfigurationError('Only proposed changes can be approved');
        }
        this.state = 'APPROVED';
        this.record('CHANGE_APPROVED', actor, this.baseline.name, 'Change approved');
    }

    apply(actor, policies) {
        if (this.state !== 'APPROVED') {
            throw new ConfigurationError('Approval is required before application');
        }

        const violations = this.evaluatePolicies(policies);
        if (violations.length) {
            this.state = 'REJECTED';
            throw new ConfigurationError(
                `Compliance blocked application: ${violations.join('; ')}`
            );
        }

        this.state = 'APPLIED';
        this.record('CHANGE_APPLIED', actor, this.baseline.name, 'Configuration applied');
    }

    remediate(actor) {
        let changed = 0;

        for (const [key, item] of this.baseline.items) {
            if (!this.current.has(key) || this.current.get(key) !== item.value) {
                this.current.set(key, item.value);
                changed++;
            }
        }

        // Remove keys outside the approved baseline.
        for (const key of [...this.current.keys()]) {
            if (!this.baseline.items.has(key)) {
                this.current.delete(key);
                changed++;
            }
        }

        this.record(
            'DRIFT_REMEDIATED',
            actor,
            this.baseline.name,
            `${changed} configuration item(s)`
        );
        return changed;
    }

    redactedSnapshot() {
        const output = {};
        for (const [key, item] of this.baseline.items) {
            output[key] = item.secret ? '<REDACTED>' : this.current.get(key);
        }
        return output;
    }
}

function createDemo() {
    const items = new Map([
        ['ssh.rootLogin', new ConfigItem('ssh.rootLogin', false)],
        ['ssh.passwordAuthentication', new ConfigItem('ssh.passwordAuthentication', false)],
        ['firewall.enabled', new ConfigItem('firewall.enabled', true)],
        ['tls.minimumVersion', new ConfigItem('tls.minimumVersion', 'TLS1.2')],
        ['audit.enabled', new ConfigItem('audit.enabled', true)],
        ['backup.retentionDays', new ConfigItem('backup.retentionDays', 30)],
        ['service.httpsPort', new ConfigItem('service.httpsPort', 443)],
        ['database.password', new ConfigItem(
            'database.password',
            'baseline-secret',
            { secret: true }
        )]
    ]);

    const baseline = new Baseline('production-web', 4, items);

    const policies = [
        {
            name: 'Root login disabled',
            key: 'ssh.rootLogin',
            severity: 'critical',
            check: value => value === false
        },
        {
            name: 'Password authentication disabled',
            key: 'ssh.passwordAuthentication',
            severity: 'high',
            check: value => value === false
        },
        {
            name: 'Firewall enabled',
            key: 'firewall.enabled',
            severity: 'critical',
            check: value => value === true
        },
        {
            name: 'TLS 1.2 or newer',
            key: 'tls.minimumVersion',
            severity: 'high',
            check: value => value === 'TLS1.2' || value === 'TLS1.3'
        },
        {
            name: 'Backup retention',
            key: 'backup.retentionDays',
            severity: 'medium',
            check: value => Number.isInteger(value) && value >= 7
        }
    ];

    return {
        baseline,
        policies,
        current: {
            ssh: undefined,
            'ssh.rootLogin': false,
            'ssh.passwordAuthentication': true,
            'firewall.enabled': true,
            'tls.minimumVersion': 'TLS1.2',
            'audit.enabled': true,
            'backup.retentionDays': 30,
            'service.httpsPort': 443,
            'database.password': 'changed-secret',
            'debug.enabled': true
        }
    };
}

async function main() {
    const { baseline, policies, current } = createDemo();
    const service = new ConfigurationService(baseline);

    service.on('audit', event => {
        console.log(`[AUDIT] ${event.action} actor=${event.actor}`);
    });

    service.load(current);

    console.log('=== Secure Configuration Management ===');
    console.log(`Baseline: ${baseline.name} v${baseline.version}`);
    console.log(`Integrity: ${baseline.verifyIntegrity()}`);

    console.log('\nDrift:');
    console.table(service.detectDrift());

    console.log('\nCompliance:');
    console.log(service.evaluatePolicies(policies));

    console.log('\nRedacted snapshot:');
    console.log(JSON.stringify(service.redactedSnapshot(), null, 2));

    service.remediate('configuration-admin');

    await service.propose(
        'configuration-admin',
        'backup.retentionDays',
        45
    );

    service.approve('security-reviewer');

    try {
        service.apply('deployment-service', policies);
        console.log('\nApproved configuration applied.');
    } catch (error) {
        console.error(error.message);
    }

    const auditPath = 'configuration-audit.json';
    await fs.writeFile(
        auditPath,
        JSON.stringify(service.audit, null, 2),
        { encoding: 'utf8', mode: 0o600 }
    );
    console.log(`Audit persisted to ${auditPath}`);

    // Secret material never appears in the exported snapshot.
    if (service.redactedSnapshot()['database.password'] !== '<REDACTED>') {
        throw new Error('Secret redaction invariant failed');
    }
}

main().catch(error => {
    console.error(`Fatal configuration-management error: ${error.message}`);
    process.exitCode = 1;
});
