'use strict';

/*
 * System Hardening policy evaluator.
 * Node.js 18+ is sufficient because only standard JavaScript features
 * are required.
 *
 * The model separates baseline compliance, attack-surface reduction,
 * service minimization, and patch-management decisions.
 */

const Severity = Object.freeze({
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical'
});

const PatchStatus = Object.freeze({
    REQUIRED: 'required',
    SCHEDULED: 'scheduled',
    INSTALLED: 'installed',
    DEFERRED: 'deferred'
});

class SecureBaseline {
    constructor({
        minimumPasswordLength = 14,
        maximumPasswordAgeDays = 90,
        firewallRequired = true,
        remoteRootLoginDisabled = true,
        auditLoggingRequired = true,
        diskEncryptionRequired = true,
        requireEncryptedExternalServices = true
    } = {}) {
        this.minimumPasswordLength = minimumPasswordLength;
        this.maximumPasswordAgeDays = maximumPasswordAgeDays;
        this.firewallRequired = firewallRequired;
        this.remoteRootLoginDisabled = remoteRootLoginDisabled;
        this.auditLoggingRequired = auditLoggingRequired;
        this.diskEncryptionRequired = diskEncryptionRequired;
        this.requireEncryptedExternalServices =
            requireEncryptedExternalServices;
    }
}

class Service {
    constructor({
        name,
        port = null,
        required,
        externallyReachable,
        encrypted
    }) {
        if (!name || !Number.isInteger(port) && port !== null) {
            throw new TypeError('Service name and valid port are required.');
        }

        if (port !== null && (port < 1 || port > 65535)) {
            throw new RangeError(`Invalid port for ${name}.`);
        }

        this.name = name;
        this.port = port;
        this.required = Boolean(required);
        this.externallyReachable = Boolean(externallyReachable);
        this.encrypted = Boolean(encrypted);
    }
}

class Vulnerability {
    constructor({
        id,
        severity,
        service,
        fixedVersion,
        dueDate,
        status = PatchStatus.REQUIRED
    }) {
        if (!Object.values(Severity).includes(severity)) {
            throw new TypeError(`Unsupported severity: ${severity}`);
        }

        if (!/^[A-Z]+-\d{4}-\d{4,}$/.test(id)) {
            throw new TypeError(`Invalid vulnerability identifier: ${id}`);
        }

        this.id = id;
        this.severity = severity;
        this.service = service;
        this.fixedVersion = fixedVersion;
        this.dueDate = new Date(`${dueDate}T00:00:00Z`);
        this.status = status;
    }
}

class Host {
    constructor({
        hostname,
        passwordLength,
        passwordAgeDays,
        firewallEnabled,
        remoteRootLogin,
        auditLogging,
        diskEncryption,
        services = [],
        vulnerabilities = []
    }) {
        if (!/^[a-z0-9][a-z0-9.-]{1,62}$/i.test(hostname)) {
            throw new TypeError(`Invalid hostname: ${hostname}`);
        }

        this.hostname = hostname;
        this.passwordLength = passwordLength;
        this.passwordAgeDays = passwordAgeDays;
        this.firewallEnabled = firewallEnabled;
        this.remoteRootLogin = remoteRootLogin;
        this.auditLogging = auditLogging;
        this.diskEncryption = diskEncryption;
        this.services = services;
        this.vulnerabilities = vulnerabilities;
    }
}

class HardeningPolicy {
    constructor(baseline) {
        this.baseline = baseline;
    }

    finding(category, severity, message, remediation) {
        return { category, severity, message, remediation };
    }

    evaluateBaseline(host) {
        const findings = [];

        if (host.passwordLength < this.baseline.minimumPasswordLength) {
            findings.push(this.finding(
                'authentication',
                Severity.HIGH,
                'Password length is below the secure baseline.',
                `Raise the minimum to ${this.baseline.minimumPasswordLength}.`
            ));
        }

        if (host.passwordAgeDays > this.baseline.maximumPasswordAgeDays) {
            findings.push(this.finding(
                'authentication',
                Severity.MEDIUM,
                'Password maximum age exceeds the baseline.',
                `Set the maximum to ${this.baseline.maximumPasswordAgeDays} days.`
            ));
        }

        if (this.baseline.firewallRequired && !host.firewallEnabled) {
            findings.push(this.finding(
                'network',
                Severity.CRITICAL,
                'Host firewall is disabled.',
                'Enable the firewall before exposing network services.'
            ));
        }

        if (
            this.baseline.remoteRootLoginDisabled &&
            host.remoteRootLogin
        ) {
            findings.push(this.finding(
                'access-control',
                Severity.CRITICAL,
                'Remote root login is enabled.',
                'Disable direct remote root authentication.'
            ));
        }

        if (this.baseline.auditLoggingRequired && !host.auditLogging) {
            findings.push(this.finding(
                'logging',
                Severity.HIGH,
                'Security audit logging is disabled.',
                'Enable centralized or protected audit logging.'
            ));
        }

        if (
            this.baseline.diskEncryptionRequired &&
            !host.diskEncryption
        ) {
            findings.push(this.finding(
                'storage',
                Severity.HIGH,
                'Disk encryption does not meet the baseline.',
                'Enable encryption and securely manage recovery keys.'
            ));
        }

        return findings;
    }

    evaluateServices(host) {
        const findings = [];

        for (const service of host.services) {
            if (!service.required) {
                findings.push(this.finding(
                    'service-minimization',
                    service.externallyReachable
                        ? Severity.HIGH
                        : Severity.MEDIUM,
                    `Unnecessary service '${service.name}' is enabled.`,
                    'Disable or remove the service after dependency validation.'
                ));
            }

            if (
                service.externallyReachable &&
                this.baseline.requireEncryptedExternalServices &&
                !service.encrypted
            ) {
                findings.push(this.finding(
                    'network-exposure',
                    Severity.HIGH,
                    `External service '${service.name}' is unencrypted.`,
                    'Restrict exposure or require an encrypted protocol.'
                ));
            }
        }

        return findings;
    }

    evaluatePatches(host, now = new Date()) {
        const findings = [];

        for (const vulnerability of host.vulnerabilities) {
            if (vulnerability.status === PatchStatus.INSTALLED) {
                continue;
            }

            const overdue =
                vulnerability.dueDate.getTime() < now.getTime();

            let severity = vulnerability.severity;
            if (vulnerability.severity === Severity.CRITICAL) {
                severity = Severity.CRITICAL;
            } else if (overdue) {
                severity = Severity.HIGH;
            }

            findings.push(this.finding(
                'patch-management',
                severity,
                `${vulnerability.id} affects ${vulnerability.service}; ` +
                `fixed version ${vulnerability.fixedVersion}.`,
                `Install or otherwise remediate before ${vulnerability.dueDate.toISOString().slice(0, 10)}.`
            ));
        }

        return findings;
    }

    evaluate(host, now = new Date()) {
        return [
            ...this.evaluateBaseline(host),
            ...this.evaluateServices(host),
            ...this.evaluatePatches(host, now)
        ];
    }

    attackSurface(host) {
        return host.services.reduce((score, service) => {
            if (!service.externallyReachable) return score;

            let contribution = 3;
            if (!service.required) contribution += 2;
            if (!service.encrypted) contribution += 3;
            return score + contribution;
        }, 0);
    }

    reduceExposure(host) {
        const actions = [];

        for (const service of host.services) {
            if (!service.required && service.externallyReachable) {
                service.externallyReachable = false;
                actions.push(
                    `Restricted external exposure for ${service.name}.`
                );
            }
        }

        return actions;
    }

    prioritizePatches(host, now = new Date()) {
        const weight = {
            [Severity.LOW]: 1,
            [Severity.MEDIUM]: 2,
            [Severity.HIGH]: 3,
            [Severity.CRITICAL]: 4
        };

        return [...host.vulnerabilities]
            .filter(vulnerability =>
                vulnerability.status !== PatchStatus.INSTALLED
            )
            .sort((a, b) => {
                const severityDifference =
                    weight[b.severity] - weight[a.severity];

                if (severityDifference !== 0) {
                    return severityDifference;
                }

                return a.dueDate - b.dueDate;
            })
            .map(vulnerability => ({
                id: vulnerability.id,
                severity: vulnerability.severity,
                overdue:
                    vulnerability.dueDate.getTime() < now.getTime(),
                dueDate:
                    vulnerability.dueDate.toISOString().slice(0, 10)
            }));
    }
}

function printFindings(findings) {
    for (const finding of findings) {
        console.log(
            `[${finding.severity.toUpperCase().padEnd(8)}] ` +
            `${finding.category.padEnd(22)} ${finding.message}`
        );
        console.log(`  Remediation: ${finding.remediation}`);
    }
}

function main() {
    const baseline = new SecureBaseline();

    const host = new Host({
        hostname: 'payments-api-01',
        passwordLength: 11,
        passwordAgeDays: 180,
        firewallEnabled: false,
        remoteRootLogin: true,
        auditLogging: false,
        diskEncryption: false,
        services: [
            new Service({
                name: 'ssh',
                port: 22,
                required: true,
                externallyReachable: true,
                encrypted: true
            }),
            new Service({
                name: 'https',
                port: 443,
                required: true,
                externallyReachable: true,
                encrypted: true
            }),
            new Service({
                name: 'telnet',
                port: 23,
                required: false,
                externallyReachable: true,
                encrypted: false
            }),
            new Service({
                name: 'legacy-ftp',
                port: 21,
                required: false,
                externallyReachable: true,
                encrypted: false
            }),
            new Service({
                name: 'node-exporter',
                port: 9100,
                required: true,
                externallyReachable: false,
                encrypted: true
            })
        ],
        vulnerabilities: [
            new Vulnerability({
                id: 'CVE-2026-10001',
                severity: Severity.CRITICAL,
                service: 'https',
                fixedVersion: '4.8.2',
                dueDate: '2026-10-18'
            }),
            new Vulnerability({
                id: 'CVE-2026-10017',
                severity: Severity.HIGH,
                service: 'ssh',
                fixedVersion: '9.9p2',
                dueDate: '2026-10-28'
            })
        ]
    });

    const policy = new HardeningPolicy(baseline);
    const now = new Date('2026-10-21T00:00:00Z');

    console.log(`Host: ${host.hostname}`);
    console.log(`Initial attack-surface score: ${policy.attackSurface(host)}`);

    console.log('\nPolicy findings:');
    printFindings(policy.evaluate(host, now));

    console.log('\nPatch priority:');
    console.table(policy.prioritizePatches(host, now));

    console.log('\nAttack-surface reduction:');
    for (const action of policy.reduceExposure(host)) {
        console.log(`- ${action}`);
    }

    console.log(
        `Final attack-surface score: ${policy.attackSurface(host)}`
    );

    console.log('\nRemaining findings:');
    printFindings(policy.evaluate(host, now));
}

main();
