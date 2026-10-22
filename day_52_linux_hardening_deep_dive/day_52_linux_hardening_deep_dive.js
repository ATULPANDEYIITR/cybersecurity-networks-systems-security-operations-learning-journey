'use strict';

/*
 * Linux Hardening Deep Dive
 *
 * Event-driven policy evaluator for SSH, sudo, filesystem permissions,
 * kernel controls, and auditing evidence.
 *
 * The program is intentionally read-only. It collects local evidence,
 * evaluates controls, emits events for each finding, and produces a
 * machine-readable report.
 */

const fs = require('node:fs/promises');
const os = require('node:os');
const { EventEmitter } = require('node:events');

const CONTROL_FILES = {
  ssh: '/etc/ssh/sshd_config',
  sudoers: '/etc/sudoers',
  passwd: '/etc/passwd',
  shadow: '/etc/shadow',
  auditStatus: '/proc/sys/kernel/audit_enabled'
};

const KERNEL_CONTROLS = {
  'kernel.randomize_va_space': {
    path: '/proc/sys/kernel/randomize_va_space',
    expected: '2'
  },
  'fs.protected_hardlinks': {
    path: '/proc/sys/fs/protected_hardlinks',
    expected: '1'
  },
  'fs.protected_symlinks': {
    path: '/proc/sys/fs/protected_symlinks',
    expected: '1'
  }
};

class Finding {
  constructor(category, control, status, severity, evidence, recommendation) {
    this.category = category;
    this.control = control;
    this.status = status;
    this.severity = severity;
    this.evidence = evidence;
    this.recommendation = recommendation;
    this.timestamp = new Date().toISOString();
  }
}

class HardeningAudit extends EventEmitter {
  constructor() {
    super();
    this.findings = [];
  }

  addFinding(...args) {
    const finding = new Finding(...args);
    this.findings.push(finding);
    this.emit('finding', finding);
  }

  async readFile(path) {
    try {
      return await fs.readFile(path, 'utf8');
    } catch (error) {
      return null;
    }
  }

  parseSshConfig(content) {
    const directives = new Map();

    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();

      if (!line || line.startsWith('#')) {
        continue;
      }

      const match = line.match(/^([A-Za-z][A-Za-z0-9]*)\s+(.+)$/);
      if (match) {
        directives.set(match[1].toLowerCase(), match[2].trim());
      }
    }

    return directives;
  }

  async auditSsh() {
    const content = await this.readFile(CONTROL_FILES.ssh);

    if (content === null) {
      this.addFinding(
        'SSH',
        'sshd_config',
        'UNKNOWN',
        'medium',
        'The SSH daemon configuration could not be read.',
        'Run the audit with permissions sufficient to inspect SSH configuration.'
      );
      return;
    }

    const config = this.parseSshConfig(content);

    const rules = [
      [
        'permitrootlogin',
        value => ['no', 'prohibit-password'].includes(value.toLowerCase()),
        'Disable direct root SSH login unless a documented exception is required.'
      ],
      [
        'passwordauthentication',
        value => value.toLowerCase() === 'no',
        'Prefer strong key-based authentication where operationally appropriate.'
      ],
      [
        'permitemptypasswords',
        value => value.toLowerCase() === 'no',
        'Explicitly disable empty-password SSH authentication.'
      ],
      [
        'x11forwarding',
        value => value.toLowerCase() === 'no',
        'Disable X11 forwarding when it is not required.'
      ]
    ];

    for (const [directive, predicate, recommendation] of rules) {
      const value = config.get(directive);

      if (value === undefined) {
        this.addFinding(
          'SSH',
          directive,
          'REVIEW',
          'medium',
          'Directive is not explicitly configured.',
          recommendation
        );
      } else if (predicate(value)) {
        this.addFinding(
          'SSH',
          directive,
          'PASS',
          'info',
          `${directive}=${value}`,
          'No immediate issue identified.'
        );
      } else {
        this.addFinding(
          'SSH',
          directive,
          'FAIL',
          'high',
          `${directive}=${value}`,
          recommendation
        );
      }
    }
  }

  async auditSudo() {
    const content = await this.readFile(CONTROL_FILES.sudoers);

    if (content === null) {
      this.addFinding(
        'sudo',
        'sudoers readability',
        'UNKNOWN',
        'medium',
        'Unable to read /etc/sudoers.',
        'Inspect sudo policy using an account with appropriate administrative access.'
      );
      return;
    }

    const lines = content.split(/\r?\n/);
    const passwordless = [];

    lines.forEach((line, index) => {
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith('#')) {
        return;
      }

      if (/NOPASSWD\s*:/i.test(trimmed)) {
        passwordless.push(`line ${index + 1}: ${trimmed}`);
      }
    });

    if (passwordless.length === 0) {
      this.addFinding(
        'sudo',
        'passwordless elevation',
        'PASS',
        'info',
        'No NOPASSWD rule was found in /etc/sudoers.',
        'Review included sudoers files as well.'
      );
    } else {
      this.addFinding(
        'sudo',
        'passwordless elevation',
        'REVIEW',
        'medium',
        passwordless.join('; '),
        'Verify that each passwordless command is narrowly scoped and operationally justified.'
      );
    }
  }

  async auditFilesystem() {
    const checks = [
      { path: CONTROL_FILES.passwd, maximum: 0o644, sensitive: false },
      { path: CONTROL_FILES.shadow, maximum: 0o640, sensitive: true },
      { path: CONTROL_FILES.sudoers, maximum: 0o440, sensitive: true }
    ];

    for (const check of checks) {
      try {
        const metadata = await fs.stat(check.path);
        const mode = metadata.mode & 0o777;

        if (check.sensitive && (mode & 0o007)) {
          this.addFinding(
            'Filesystem permissions',
            check.path,
            'FAIL',
            'high',
            `Mode ${mode.toString(8).padStart(4, '0')} permits world access.`,
            'Remove unnecessary world permissions and verify owner/group ownership.'
          );
        } else if ((mode & ~check.maximum) !== 0) {
          this.addFinding(
            'Filesystem permissions',
            check.path,
            'REVIEW',
            'medium',
            `Mode ${mode.toString(8).padStart(4, '0')} exceeds baseline ${check.maximum.toString(8)}.`,
            'Confirm every additional permission is intentional.'
          );
        } else {
          this.addFinding(
            'Filesystem permissions',
            check.path,
            'PASS',
            'info',
            `Mode ${mode.toString(8).padStart(4, '0')}`,
            'No excessive permission detected against the audit baseline.'
          );
        }
      } catch (error) {
        this.addFinding(
          'Filesystem permissions',
          check.path,
          'UNKNOWN',
          'medium',
          error.message,
          'Inspect the file manually with appropriate privileges.'
        );
      }
    }
  }

  async auditKernel() {
    for (const [name, control] of Object.entries(KERNEL_CONTROLS)) {
      const content = await this.readFile(control.path);

      if (content === null) {
        this.addFinding(
          'Kernel controls',
          name,
          'UNKNOWN',
          'medium',
          `Unable to read ${control.path}.`,
          'Verify the control manually.'
        );
        continue;
      }

      const actual = content.trim();

      if (actual === control.expected) {
        this.addFinding(
          'Kernel controls',
          name,
          'PASS',
          'info',
          `Value ${actual}`,
          'No immediate issue identified.'
        );
      } else {
        this.addFinding(
          'Kernel controls',
          name,
          'FAIL',
          'high',
          `Value ${actual}; expected ${control.expected}.`,
          `Evaluate ${name} using the Linux distribution's supported persistent configuration method.`
        );
      }
    }
  }

  async auditAuditSubsystem() {
    const value = await this.readFile(CONTROL_FILES.auditStatus);

    if (value === null) {
      this.addFinding(
        'Auditing',
        'kernel audit status',
        'UNKNOWN',
        'medium',
        'Unable to read kernel audit status.',
        'Inspect auditd/audit subsystem status with administrative privileges.'
      );
      return;
    }

    if (value.trim() === '1') {
      this.addFinding(
        'Auditing',
        'kernel audit status',
        'PASS',
        'info',
        'kernel audit interface reports enabled.',
        'Verify that persistent audit rules cover required security events.'
      );
    } else {
      this.addFinding(
        'Auditing',
        'kernel audit status',
        'REVIEW',
        'high',
        `kernel audit status=${value.trim()}`,
        'Verify the active auditing architecture and persistent audit configuration.'
      );
    }
  }

  async run() {
    await this.auditSsh();
    await this.auditSudo();
    await this.auditFilesystem();
    await this.auditKernel();
    await this.auditAuditSubsystem();
    return this.findings;
  }
}

async function main() {
  if (process.platform !== 'linux') {
    console.error('This program requires Linux.');
    process.exitCode = 2;
    return;
  }

  const audit = new HardeningAudit();

  audit.on('finding', finding => {
    process.stderr.write(
      `[${finding.status}] ${finding.category}: ${finding.control}\n`
    );
  });

  const findings = await audit.run();

  const report = {
    generatedAt: new Date().toISOString(),
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    findings,
    counts: findings.reduce((counts, finding) => {
      counts[finding.status] = (counts[finding.status] || 0) + 1;
      return counts;
    }, {})
  };

  console.log(JSON.stringify(report, null, 2));

  if (findings.some(finding => finding.status === 'FAIL')) {
    process.exitCode = 1;
  }
}

main().catch(error => {
  console.error(`Audit failed: ${error.message}`);
  process.exitCode = 2;
});
