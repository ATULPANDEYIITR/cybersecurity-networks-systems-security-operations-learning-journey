"use strict";

/*
 * Linux Security Governance Lab
 *
 * This Node.js program models SSH access, sudo authorization, Unix-style
 * permissions, secure host configuration, service minimization, and the
 * relationships between these controls.
 *
 * It deliberately performs policy evaluation in memory rather than changing
 * the operating system. No third-party npm package is required.
 */

const AuthenticationMethod = Object.freeze({
    PASSWORD: "password",
    PUBLIC_KEY: "public_key",
    CERTIFICATE: "certificate"
});

const Severity = Object.freeze({
    INFO: "INFO",
    LOW: "LOW",
    MEDIUM: "MEDIUM",
    HIGH: "HIGH",
    CRITICAL: "CRITICAL"
});

class Finding {
    constructor(area, severity, title, detail, recommendation) {
        this.area = area;
        this.severity = severity;
        this.title = title;
        this.detail = detail;
        this.recommendation = recommendation;
    }

    toString() {
        return [
            `[${this.severity.padEnd(8)}] ${this.area}: ${this.title}`,
            `           ${this.detail}`,
            `           Recommendation: ${this.recommendation}`
        ].join("\n");
    }
}

class SSHPolicy {
    constructor({
        permitRootLogin = false,
        passwordAuthentication = false,
        publicKeyAuthentication = true,
        allowedUsers = [],
        allowedGroups = [],
        maxAuthTries = 3,
        x11Forwarding = false,
        agentForwarding = false,
        tcpForwarding = false
    } = {}) {
        this.permitRootLogin = permitRootLogin;
        this.passwordAuthentication = passwordAuthentication;
        this.publicKeyAuthentication = publicKeyAuthentication;
        this.allowedUsers = new Set(allowedUsers);
        this.allowedGroups = new Set(allowedGroups);
        this.maxAuthTries = maxAuthTries;
        this.x11Forwarding = x11Forwarding;
        this.agentForwarding = agentForwarding;
        this.tcpForwarding = tcpForwarding;
    }

    evaluate(user, method, attempts = 1, credentialValid = true) {
        if (!user) {
            return { allowed: false, reason: "Unknown account." };
        }

        if (user.locked) {
            return { allowed: false, reason: "Account is locked." };
        }

        if (user.root && !this.permitRootLogin) {
            return {
                allowed: false,
                reason: "Direct root SSH login is disabled."
            };
        }

        if (
            this.allowedUsers.size > 0 &&
            !this.allowedUsers.has(user.username)
        ) {
            return {
                allowed: false,
                reason: "Account is outside the AllowUsers policy."
            };
        }

        if (
            this.allowedGroups.size > 0 &&
            ![...user.groups].some(group => this.allowedGroups.has(group))
        ) {
            return {
                allowed: false,
                reason: "User is outside the allowed SSH groups."
            };
        }

        if (attempts > this.maxAuthTries) {
            return {
                allowed: false,
                reason: "Maximum authentication attempts exceeded."
            };
        }

        if (
            method === AuthenticationMethod.PASSWORD &&
            !this.passwordAuthentication
        ) {
            return {
                allowed: false,
                reason: "Password authentication is disabled."
            };
        }

        if (
            method === AuthenticationMethod.PUBLIC_KEY &&
            (!this.publicKeyAuthentication || !user.publicKeyConfigured)
        ) {
            return {
                allowed: false,
                reason: !this.publicKeyAuthentication
                    ? "Public-key authentication is disabled."
                    : "User has no configured public key."
            };
        }

        if (!credentialValid) {
            return {
                allowed: false,
                reason: "Credential verification failed."
            };
        }

        return {
            allowed: true,
            reason: "SSH policy permits the connection."
        };
    }

    audit() {
        const findings = [];

        if (this.permitRootLogin) {
            findings.push(new Finding(
                "SSH",
                Severity.CRITICAL,
                "Direct root login enabled",
                "Remote clients can authenticate directly as root.",
                "Disable direct root SSH login and use a controlled administrative account."
            ));
        }

        if (this.passwordAuthentication) {
            findings.push(new Finding(
                "SSH",
                Severity.HIGH,
                "Password authentication enabled",
                "SSH accepts password-based authentication.",
                "Prefer public-key authentication and disable passwords when operationally safe."
            ));
        }

        if (this.maxAuthTries > 4) {
            findings.push(new Finding(
                "SSH",
                Severity.MEDIUM,
                "High authentication retry limit",
                `MaxAuthTries is ${this.maxAuthTries}.`,
                "Use a restrictive authentication retry limit."
            ));
        }

        if (this.x11Forwarding) {
            findings.push(new Finding(
                "SSH",
                Severity.MEDIUM,
                "X11 forwarding enabled",
                "SSH sessions can request X11 forwarding.",
                "Disable X11 forwarding unless explicitly required."
            ));
        }

        if (this.agentForwarding) {
            findings.push(new Finding(
                "SSH",
                Severity.MEDIUM,
                "Agent forwarding enabled",
                "Forwarded SSH agents can expose credentials through compromised hosts.",
                "Disable agent forwarding unless required by the connection workflow."
            ));
        }

        if (this.tcpForwarding) {
            findings.push(new Finding(
                "SSH",
                Severity.MEDIUM,
                "TCP forwarding enabled",
                "Users can create SSH tunnels.",
                "Disable forwarding unless tunneling is an approved requirement."
            ));
        }

        return findings;
    }
}

class SudoPolicy {
    constructor(rules) {
        this.rules = rules;
    }

    authorize(username, command) {
        const matchingRule = this.rules.find(rule => {
            const userMatch =
                rule.users.includes("ALL") || rule.users.includes(username);

            const commandMatch =
                rule.commands.includes("ALL") ||
                rule.commands.includes(command);

            return userMatch && commandMatch;
        });

        if (!matchingRule) {
            return {
                allowed: false,
                reason: "No sudo rule authorizes the command."
            };
        }

        return {
            allowed: true,
            reason: [
                `run_as=${matchingRule.runAs}`,
                `password_required=${matchingRule.requirePassword}`,
                `noexec=${matchingRule.noexec}`
            ].join(", ")
        };
    }

    audit() {
        const findings = [];

        for (const rule of this.rules) {
            if (
                rule.users.includes("ALL") &&
                rule.commands.includes("ALL")
            ) {
                findings.push(new Finding(
                    "sudo",
                    Severity.CRITICAL,
                    "Unrestricted sudo policy",
                    "Every user is authorized to execute every command.",
                    "Replace broad authorization with explicit users and commands."
                ));
            } else if (rule.commands.includes("ALL")) {
                findings.push(new Finding(
                    "sudo",
                    Severity.HIGH,
                    "Broad sudo command scope",
                    `Users ${rule.users.join(", ")} can execute all commands.`,
                    "Apply least privilege and authorize only required commands."
                ));
            }

            if (!rule.requirePassword) {
                findings.push(new Finding(
                    "sudo",
                    Severity.MEDIUM,
                    "Passwordless sudo",
                    `Users ${rule.users.join(", ")} can execute configured commands without password authentication.`,
                    "Use passwordless sudo only for tightly controlled automation."
                ));
            }
        }

        return findings;
    }
}

class PermissionEngine {
    constructor(objects) {
        this.objects = new Map(objects.map(object => [object.path, object]));
    }

    permissionClass(object, username, groups) {
        if (object.owner === username) {
            return {
                label: "owner",
                bits: (object.mode >> 6) & 7
            };
        }

        if (groups.has(object.group)) {
            return {
                label: "group",
                bits: (object.mode >> 3) & 7
            };
        }

        return {
            label: "other",
            bits: object.mode & 7
        };
    }

    canAccess(path, username, groups, action) {
        const object = this.objects.get(path);

        if (!object) {
            return {
                allowed: false,
                reason: "Path does not exist in the model."
            };
        }

        const requiredBits = {
            read: 4,
            write: 2,
            execute: 1
        };

        if (!(action in requiredBits)) {
            return {
                allowed: false,
                reason: "Unsupported access operation."
            };
        }

        const selected = this.permissionClass(object, username, groups);
        const allowed =
            (selected.bits & requiredBits[action]) === requiredBits[action];

        return {
            allowed,
            reason: allowed
                ? `Allowed by ${selected.label} permission bits.`
                : `Denied by ${selected.label} permission bits.`
        };
    }

    audit() {
        const findings = [];

        for (const object of this.objects.values()) {
            const mode = object.mode & 0o777;

            if (mode & 0o002) {
                findings.push(new Finding(
                    "Permissions",
                    Severity.HIGH,
                    "World-writable object",
                    `${object.path} has mode ${mode.toString(8).padStart(3, "0")}.`,
                    "Remove write access for unrelated users."
                ));
            }

            if (!object.directory && mode & 0o004) {
                findings.push(new Finding(
                    "Permissions",
                    Severity.MEDIUM,
                    "World-readable file",
                    `${object.path} is readable by other users.`,
                    "Restrict access to the required owner or group."
                ));
            }

            if (object.mode & 0o4000) {
                findings.push(new Finding(
                    "Permissions",
                    Severity.HIGH,
                    "Setuid executable",
                    `${object.path} carries the setuid bit.`,
                    "Verify that privileged execution is necessary and that the executable is trusted."
                ));
            }
        }

        return findings;
    }
}

class ConfigurationPolicy {
    constructor(settings) {
        this.settings = settings;
    }

    audit() {
        const checks = [
            [
                "firewallEnabled",
                "Firewall disabled",
                Severity.HIGH,
                "Host network exposure is not constrained by a local firewall.",
                "Enable a host firewall with a minimal permitted traffic set."
            ],
            [
                "automaticSecurityUpdates",
                "Automatic security updates disabled",
                Severity.MEDIUM,
                "Security fixes may remain unapplied.",
                "Use controlled automatic patching or an equivalent patch-management process."
            ],
            [
                "auditLogging",
                "Security audit logging disabled",
                Severity.HIGH,
                "Authentication and authorization events may not be available for investigation.",
                "Enable appropriate security and system logging."
            ],
            [
                "timeSynchronization",
                "Time synchronization disabled",
                Severity.MEDIUM,
                "Security event timestamps may become inconsistent.",
                "Use a trusted time synchronization mechanism."
            ],
            [
                "coreDumpsRestricted",
                "Core dumps are unrestricted",
                Severity.MEDIUM,
                "Crash artifacts may contain sensitive process memory.",
                "Restrict core dumps according to operational requirements."
            ],
            [
                "fileIntegrityMonitoring",
                "File integrity monitoring disabled",
                Severity.MEDIUM,
                "Unexpected modifications to sensitive files may go undetected.",
                "Monitor critical configuration and executable paths."
            ]
        ];

        return checks
            .filter(([property]) => !this.settings[property])
            .map(([, title, severity, detail, recommendation]) =>
                new Finding(
                    "Secure configuration",
                    severity,
                    title,
                    detail,
                    recommendation
                )
            );
    }
}

class ServiceMinimizer {
    constructor(services) {
        this.services = services;
    }

    audit() {
        const findings = [];

        for (const service of this.services) {
            if (!service.businessRequired && service.enabledAtBoot) {
                findings.push(new Finding(
                    "Services",
                    Severity.HIGH,
                    "Unnecessary enabled service",
                    `${service.name} starts at boot but is not business-required.`,
                    "Disable or remove the service."
                ));
            }

            if (!service.businessRequired && service.ports.length > 0) {
                findings.push(new Finding(
                    "Services",
                    Severity.HIGH,
                    "Unnecessary network listener",
                    `${service.name} listens on ${service.ports.join(", ")}.`,
                    "Stop the service or remove unnecessary network exposure."
                ));
            }

            if (service.remoteReachable && service.ports.length > 0) {
                findings.push(new Finding(
                    "Services",
                    Severity.MEDIUM,
                    "Remote service exposure",
                    `${service.name} is remotely reachable on ${service.ports.join(", ")}.`,
                    "Verify that each exposed listener is necessary."
                ));
            }
        }

        return findings;
    }
}

class LinuxSecurityEngine {
    constructor({ ssh, sudo, permissions, configuration, services }) {
        this.ssh = ssh;
        this.sudo = sudo;
        this.permissions = permissions;
        this.configuration = configuration;
        this.services = services;
    }

    collectFindings() {
        return [
            ...this.ssh.audit(),
            ...this.sudo.audit(),
            ...this.permissions.audit(),
            ...this.configuration.audit(),
            ...this.services.audit()
        ];
    }

    score() {
        const penalties = {
            [Severity.INFO]: 0,
            [Severity.LOW]: 2,
            [Severity.MEDIUM]: 5,
            [Severity.HIGH]: 10,
            [Severity.CRITICAL]: 20
        };

        const total = this.collectFindings()
            .reduce((sum, finding) => sum + penalties[finding.severity], 0);

        return Math.max(0, 100 - total);
    }

    printReport() {
        const findings = this.collectFindings();

        console.log("\n=== Linux Security Assessment ===");
        console.log(`Security posture score: ${this.score()}/100`);
        console.log(`Findings: ${findings.length}`);

        for (const finding of findings) {
            console.log(`\n${finding.toString()}`);
        }
    }
}

function buildSystem() {
    const users = [
        {
            username: "opsadmin",
            groups: new Set(["linux-admins"]),
            root: false,
            locked: false,
            publicKeyConfigured: true
        },
        {
            username: "developer",
            groups: new Set(["developers"]),
            root: false,
            locked: false,
            publicKeyConfigured: true
        },
        {
            username: "legacy",
            groups: new Set(["legacy-users"]),
            root: false,
            locked: false,
            publicKeyConfigured: false
        },
        {
            username: "root",
            groups: new Set(["root"]),
            root: true,
            locked: false,
            publicKeyConfigured: true
        }
    ];

    const userMap = new Map(users.map(user => [user.username, user]));

    const ssh = new SSHPolicy({
        permitRootLogin: false,
        passwordAuthentication: false,
        publicKeyAuthentication: true,
        allowedUsers: ["opsadmin", "developer"],
        allowedGroups: ["linux-admins"],
        maxAuthTries: 3,
        x11Forwarding: false,
        agentForwarding: false,
        tcpForwarding: false
    });

    const sudo = new SudoPolicy([
        {
            users: ["opsadmin"],
            commands: [
                "/usr/bin/systemctl restart nginx",
                "/usr/bin/systemctl status nginx"
            ],
            runAs: "root",
            requirePassword: true,
            noexec: true
        },
        {
            users: ["developer"],
            commands: ["/usr/bin/journalctl"],
            runAs: "root",
            requirePassword: true,
            noexec: true
        }
    ]);

    const permissions = new PermissionEngine([
        {
            path: "/etc/ssh/sshd_config",
            owner: "root",
            group: "root",
            mode: 0o600,
            directory: false
        },
        {
            path: "/etc/shadow",
            owner: "root",
            group: "shadow",
            mode: 0o640,
            directory: false
        },
        {
            path: "/srv/app",
            owner: "deploy",
            group: "app",
            mode: 0o750,
            directory: true
        },
        {
            path: "/tmp/uploads",
            owner: "deploy",
            group: "app",
            mode: 0o777,
            directory: true
        },
        {
            path: "/usr/local/bin/privileged-helper",
            owner: "root",
            group: "root",
            mode: 0o4755,
            directory: false
        }
    ]);

    const configuration = new ConfigurationPolicy({
        firewallEnabled: true,
        automaticSecurityUpdates: true,
        auditLogging: true,
        timeSynchronization: true,
        coreDumpsRestricted: true,
        fileIntegrityMonitoring: false
    });

    const services = new ServiceMinimizer([
        {
            name: "sshd",
            enabledAtBoot: true,
            ports: [22],
            businessRequired: true,
            remoteReachable: true
        },
        {
            name: "nginx",
            enabledAtBoot: true,
            ports: [443],
            businessRequired: true,
            remoteReachable: true
        },
        {
            name: "telnet",
            enabledAtBoot: true,
            ports: [23],
            businessRequired: false,
            remoteReachable: true
        },
        {
            name: "cups",
            enabledAtBoot: true,
            ports: [631],
            businessRequired: false,
            remoteReachable: false
        }
    ]);

    return {
        userMap,
        engine: new LinuxSecurityEngine({
            ssh,
            sudo,
            permissions,
            configuration,
            services
        })
    };
}

function demonstrateEventDrivenSSH(engine, userMap) {
    console.log("\n=== Event-driven SSH evaluation ===");

    const events = [
        {
            type: "ssh_login_attempt",
            username: "opsadmin",
            method: AuthenticationMethod.PUBLIC_KEY,
            attempts: 1
        },
        {
            type: "ssh_login_attempt",
            username: "legacy",
            method: AuthenticationMethod.PASSWORD,
            attempts: 1
        },
        {
            type: "ssh_login_attempt",
            username: "root",
            method: AuthenticationMethod.PUBLIC_KEY,
            attempts: 1
        },
        {
            type: "ssh_login_attempt",
            username: "opsadmin",
            method: AuthenticationMethod.PUBLIC_KEY,
            attempts: 5
        }
    ];

    for (const event of events) {
        const user = userMap.get(event.username);
        const result = engine.ssh.evaluate(
            user,
            event.method,
            event.attempts
        );

        console.log(
            `${result.allowed ? "ALLOW" : "DENY"} ` +
            `${event.username} -> ${result.reason}`
        );
    }
}

function demonstrateSudo(engine) {
    console.log("\n=== sudo decisions ===");

    const requests = [
        ["opsadmin", "/usr/bin/systemctl restart nginx"],
        ["opsadmin", "/bin/bash"],
        ["developer", "/usr/bin/journalctl"],
        ["developer", "/usr/bin/systemctl restart nginx"]
    ];

    for (const [username, command] of requests) {
        const result = engine.sudo.authorize(username, command);
        console.log(
            `${result.allowed ? "ALLOW" : "DENY"} ` +
            `${username} -> sudo ${command}: ${result.reason}`
        );
    }
}

function demonstratePermissions(engine) {
    console.log("\n=== Permission decisions ===");

    const requests = [
        ["/etc/ssh/sshd_config", "developer", new Set(["developers"]), "read"],
        ["/etc/ssh/sshd_config", "root", new Set(["root"]), "read"],
        ["/srv/app", "developer", new Set(["developers"]), "execute"],
        ["/tmp/uploads", "developer", new Set(["developers"]), "write"]
    ];

    for (const [path, username, groups, action] of requests) {
        const result = engine.permissions.canAccess(
            path,
            username,
            groups,
            action
        );

        console.log(
            `${result.allowed ? "ALLOW" : "DENY"} ` +
            `${username} ${action} ${path}: ${result.reason}`
        );
    }
}

function main() {
    console.log("Linux Security Governance Lab");
    console.log("Policy simulation only; no operating-system settings are changed.");

    const { userMap, engine } = buildSystem();

    demonstrateEventDrivenSSH(engine, userMap);
    demonstrateSudo(engine);
    demonstratePermissions(engine);

    console.log("\n=== Security relationships ===");
    console.log(
        "SSH establishes the remote authentication boundary; sudo controls " +
        "privileged command authorization after login."
    );
    console.log(
        "Filesystem permissions independently determine access to objects, " +
        "while secure configuration reduces dangerous host behavior."
    );
    console.log(
        "Service minimization removes unnecessary software and listeners, " +
        "reducing the exposed attack surface."
    );

    engine.printReport();
}

main();
