'use strict';

/*
 * Windows Hardening Policy Engine
 *
 * This Node.js program evaluates endpoint telemetry against a defensive
 * baseline. It does not change Windows configuration. It demonstrates
 * event-driven evaluation, policy objects, validation, asynchronous
 * assessment, and generation of reviewable PowerShell diagnostics.
 */

const readline = require('node:readline');

const Enforcement = Object.freeze({
    AUDIT: 'Audit',
    BLOCK: 'Block',
    ALLOW: 'Allow',
    DISABLED: 'Disabled'
});

const Severity = Object.freeze({
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low'
});

const ASR_RULES = Object.freeze([
    Object.freeze({
        id: 'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
        name: 'Block executable content from email client and webmail',
        state: Enforcement.BLOCK,
        severity: Severity.HIGH
    }),
    Object.freeze({
        id: '3b576869-a4ec-4529-8536-b80a7769e899',
        name: 'Block Office applications from creating executable content',
        state: Enforcement.BLOCK,
        severity: Severity.HIGH
    }),
    Object.freeze({
        id: '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
        name: 'Block Office applications from injecting code into other processes',
        state: Enforcement.BLOCK,
        severity: Severity.HIGH
    }),
    Object.freeze({
        id: '26190899-1602-49e8-8b27-eb1d0a1ce869',
        name: 'Block Office communication applications from creating child processes',
        state: Enforcement.AUDIT,
        severity: Severity.MEDIUM
    })
]);

class ValidationError extends Error {}

class HardeningFinding {
    constructor(control, severity, message, remediation) {
        this.control = control;
        this.severity = severity;
        this.message = message;
        this.remediation = remediation;
    }
}

class WindowsHardeningPolicy {
    constructor(defender, firewall, security, applicationControl, asrRules) {
        this.defender = defender;
        this.firewall = firewall;
        this.security = security;
        this.applicationControl = applicationControl;
        this.asrRules = asrRules;
        this.validate();
    }

    validate() {
        if (!this.defender.realtimeMonitoring ||
            !this.defender.behaviorMonitoring ||
            !this.defender.ioavProtection ||
            !this.defender.cloudProtection ||
            !this.defender.tamperProtection) {
            throw new ValidationError('The baseline must enable core Defender protections.');
        }

        if (this.defender.signatureAgeHours < 0) {
            throw new ValidationError('Signature age cannot be negative.');
        }

        for (const profile of ['Domain', 'Private', 'Public']) {
            const value = this.firewall[profile];
            if (!value || value.enabled !== true) {
                throw new ValidationError(`${profile} firewall must be enabled in the baseline.`);
            }
            if (value.defaultInbound !== 'Block') {
                throw new ValidationError(`${profile} inbound traffic must default to Block.`);
            }
        }

        if (this.security.passwordMinimumLength < 1 ||
            this.security.lockoutThreshold < 1) {
            throw new ValidationError('Security policy contains invalid thresholds.');
        }

        if (this.applicationControl.mode !== Enforcement.BLOCK) {
            throw new ValidationError('Application control baseline must use Block mode.');
        }
    }
}

class EndpointAssessment {
    constructor(endpoint, baseline) {
        this.endpoint = structuredClone(endpoint);
        this.baseline = baseline;
        this.findings = [];
        this.validateEndpoint();
    }

    validateEndpoint() {
        if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(this.endpoint.hostname)) {
            throw new ValidationError('Invalid Windows hostname.');
        }

        if (!Array.isArray(this.endpoint.firewallProfiles) ||
            this.endpoint.firewallProfiles.length !== 3) {
            throw new ValidationError('Exactly three Windows firewall profiles are required.');
        }
    }

    add(control, severity, message, remediation) {
        this.findings.push(new HardeningFinding(
            control,
            severity,
            message,
            remediation
        ));
    }

    evaluateDefender() {
        const actual = this.endpoint.defender;
        const expected = this.baseline.defender;

        const checks = [
            ['realtimeMonitoring', 'Real-time monitoring', Severity.CRITICAL],
            ['behaviorMonitoring', 'Behavior monitoring', Severity.HIGH],
            ['ioavProtection', 'IOAV protection', Severity.HIGH],
            ['cloudProtection', 'Cloud protection', Severity.HIGH],
            ['tamperProtection', 'Tamper protection', Severity.CRITICAL]
        ];

        for (const [key, label, severity] of checks) {
            if (expected[key] && !actual[key]) {
                this.add(
                    'Microsoft Defender',
                    severity,
                    `${label} is disabled.`,
                    `Enable ${label.toLowerCase()}.`
                );
            }
        }

        if (actual.signatureAgeHours > expected.signatureAgeHours) {
            this.add(
                'Microsoft Defender',
                Severity.HIGH,
                `Security intelligence is ${actual.signatureAgeHours} hours old.`,
                `Update security intelligence within ${expected.signatureAgeHours} hours.`
            );
        }
    }

    evaluateFirewall() {
        const profiles = new Map(
            this.endpoint.firewallProfiles.map(profile => [profile.name, profile])
        );

        for (const [name, expected] of Object.entries(this.baseline.firewall)) {
            const actual = profiles.get(name);

            if (!actual) {
                this.add(
                    'Windows Firewall',
                    Severity.CRITICAL,
                    `${name} profile telemetry is missing.`,
                    `Collect ${name} firewall profile state.`
                );
                continue;
            }

            if (expected.enabled && !actual.enabled) {
                this.add(
                    'Windows Firewall',
                    name === 'Public' ? Severity.CRITICAL : Severity.HIGH,
                    `${name} firewall profile is disabled.`,
                    `Enable the ${name} firewall profile.`
                );
            }

            if (actual.defaultInbound !== expected.defaultInbound) {
                this.add(
                    'Windows Firewall',
                    Severity.HIGH,
                    `${name} inbound default action is ${actual.defaultInbound}.`,
                    `Set ${name} inbound default action to ${expected.defaultInbound}.`
                );
            }
        }
    }

    evaluateSecurityPolicy() {
        const actual = this.endpoint.security;
        const expected = this.baseline.security;

        if (actual.passwordMinimumLength < expected.passwordMinimumLength) {
            this.add(
                'Security Policy',
                Severity.MEDIUM,
                `Password minimum is ${actual.passwordMinimumLength}.`,
                `Require at least ${expected.passwordMinimumLength} characters.`
            );
        }

        if (actual.lockoutThreshold === 0 ||
            actual.lockoutThreshold > expected.lockoutThreshold) {
            this.add(
                'Security Policy',
                Severity.MEDIUM,
                'Account lockout threshold is weaker than the baseline.',
                `Set the lockout threshold to ${expected.lockoutThreshold}.`
            );
        }

        const auditChecks = [
            ['auditLogonEvents', 'Logon auditing'],
            ['auditProcessCreation', 'Process creation auditing'],
            ['powershellScriptBlockLogging', 'PowerShell script block logging'],
            ['powershellTranscription', 'PowerShell transcription']
        ];

        for (const [key, label] of auditChecks) {
            if (expected[key] && !actual[key]) {
                this.add(
                    'Security Policy',
                    label.startsWith('PowerShell') ? Severity.HIGH : Severity.MEDIUM,
                    `${label} is disabled.`,
                    `Enable ${label.toLowerCase()}.`
                );
            }
        }
    }

    evaluateApplicationControl() {
        const actual = this.endpoint.applicationControl;
        const expected = this.baseline.applicationControl;

        if (actual.mode !== expected.mode) {
            this.add(
                'Application Control',
                Severity.HIGH,
                `Application control mode is ${actual.mode}.`,
                `Use ${expected.mode} mode.`
            );
        }

        for (const key of ['publisherRules', 'pathRules', 'unsignedBinaryBlocking']) {
            if (expected[key] && !actual[key]) {
                this.add(
                    'Application Control',
                    Severity.HIGH,
                    `${key} is disabled.`,
                    `Enable ${key}.`
                );
            }
        }
    }

    evaluateAsr() {
        for (const rule of this.baseline.asrRules) {
            const actual = this.endpoint.asrRules[rule.id] ?? Enforcement.DISABLED;

            if (actual !== rule.state) {
                this.add(
                    'Attack Surface Reduction',
                    rule.severity,
                    `${rule.name} is ${actual}; baseline requires ${rule.state}.`,
                    `Set ASR rule ${rule.id} to ${rule.state}.`
                );
            }
        }
    }

    async evaluate() {
        /*
         * Yielding between policy groups models a telemetry pipeline in which
         * Defender, firewall, audit, and application-control data can arrive
         * independently.
         */
        await Promise.resolve();
        this.evaluateDefender();

        await Promise.resolve();
        this.evaluateFirewall();

        await Promise.resolve();
        this.evaluateSecurityPolicy();

        await Promise.resolve();
        this.evaluateApplicationControl();

        await Promise.resolve();
        this.evaluateAsr();

        return this.findings;
    }
}

class EventBus {
    constructor() {
        this.listeners = new Map();
    }

    on(eventName, listener) {
        if (!this.listeners.has(eventName)) {
            this.listeners.set(eventName, []);
        }
        this.listeners.get(eventName).push(listener);
    }

    emit(eventName, payload) {
        for (const listener of this.listeners.get(eventName) ?? []) {
            listener(payload);
        }
    }
}

function buildBaseline() {
    return new WindowsHardeningPolicy(
        {
            realtimeMonitoring: true,
            behaviorMonitoring: true,
            ioavProtection: true,
            cloudProtection: true,
            tamperProtection: true,
            signatureAgeHours: 24
        },
        {
            Domain: { enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow' },
            Private: { enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow' },
            Public: { enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow' }
        },
        {
            passwordMinimumLength: 14,
            lockoutThreshold: 5,
            auditLogonEvents: true,
            auditProcessCreation: true,
            powershellScriptBlockLogging: true,
            powershellTranscription: true
        },
        {
            mode: Enforcement.BLOCK,
            publisherRules: true,
            pathRules: true,
            unsignedBinaryBlocking: true
        },
        ASR_RULES
    );
}

function buildEndpoint() {
    return {
        hostname: 'WIN-FIN-017',
        defender: {
            realtimeMonitoring: true,
            behaviorMonitoring: true,
            ioavProtection: true,
            cloudProtection: true,
            tamperProtection: false,
            signatureAgeHours: 42
        },
        firewallProfiles: [
            { name: 'Domain', enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow' },
            { name: 'Private', enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow' },
            { name: 'Public', enabled: false, defaultInbound: 'Allow', defaultOutbound: 'Allow' }
        ],
        security: {
            passwordMinimumLength: 12,
            lockoutThreshold: 10,
            auditLogonEvents: true,
            auditProcessCreation: false,
            powershellScriptBlockLogging: true,
            powershellTranscription: false
        },
        applicationControl: {
            mode: Enforcement.AUDIT,
            publisherRules: true,
            pathRules: false,
            unsignedBinaryBlocking: false
        },
        asrRules: {
            [ASR_RULES[0].id]: Enforcement.BLOCK,
            [ASR_RULES[1].id]: Enforcement.AUDIT,
            [ASR_RULES[2].id]: Enforcement.BLOCK
        }
    };
}

function remediationCommands(findings) {
    const commands = new Set();

    for (const finding of findings) {
        switch (finding.control) {
            case 'Microsoft Defender':
                commands.add(
                    'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AMServiceEnabled'
                );
                break;
            case 'Windows Firewall':
                commands.add(
                    'Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction'
                );
                break;
            case 'Security Policy':
                commands.add('auditpol /get /category:*');
                break;
            case 'Application Control':
                commands.add('Get-AppLockerPolicy -Effective | Format-List');
                break;
            case 'Attack Surface Reduction':
                commands.add(
                    'Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions'
                );
                break;
        }
    }

    return [...commands];
}

async function main() {
    const baseline = buildBaseline();
    const endpoint = buildEndpoint();
    const bus = new EventBus();

    bus.on('finding', finding => {
        process.stdout.write(
            `[${finding.severity}] ${finding.control}: ${finding.message}\n`
        );
    });

    const assessment = new EndpointAssessment(endpoint, baseline);
    const findings = await assessment.evaluate();

    console.log(`Endpoint: ${endpoint.hostname}`);
    console.log(`Findings: ${findings.length}`);

    for (const finding of findings) {
        bus.emit('finding', finding);
        console.log(`  Remediation: ${finding.remediation}`);
    }

    console.log('\nReviewable diagnostic commands:');
    for (const command of remediationCommands(findings)) {
        console.log(`  ${command}`);
    }

    console.log('\nNo Windows configuration was changed.');
}

main().catch(error => {
    console.error(`Assessment failed: ${error.message}`);
    process.exitCode = 1;
});
