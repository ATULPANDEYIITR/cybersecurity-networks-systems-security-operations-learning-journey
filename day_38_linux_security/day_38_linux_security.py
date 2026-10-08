#!/usr/bin/env python3
"""
Linux Security Lab
==================

A self-contained simulation and analysis tool for five closely related Linux
security areas:

    SSH
    sudo
    file permissions
    secure configuration
    service minimization

The program intentionally models security controls instead of modifying the
host operating system. It can therefore be executed safely on Linux, macOS,
Windows, or another Python environment.

The model reflects common Linux administration practices:
- SSH access is restricted by account, authentication method, and policy.
- sudo authorization is evaluated separately from ordinary file permissions.
- Unix permission bits and ownership determine filesystem access.
- Security configuration is represented as explicit controls.
- Running services are compared with an approved service inventory.
- A combined governance engine determines whether a host satisfies policy.

No third-party packages are required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Dict, Iterable, List, Optional, Set, Tuple


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    area: str
    severity: Severity
    title: str
    detail: str
    recommendation: str

    def display(self) -> str:
        return (
            f"[{self.severity.value:<8}] {self.area}: {self.title}\n"
            f"           {self.detail}\n"
            f"           Recommendation: {self.recommendation}"
        )


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

class AuthenticationMethod(Enum):
    PASSWORD = "password"
    PUBLIC_KEY = "public_key"
    CERTIFICATE = "certificate"


@dataclass
class SSHConfig:
    permit_root_login: str = "no"
    password_authentication: bool = False
    pubkey_authentication: bool = True
    allow_users: Set[str] = field(default_factory=set)
    allow_groups: Set[str] = field(default_factory=set)
    max_auth_tries: int = 3
    x11_forwarding: bool = False
    agent_forwarding: bool = False
    tcp_forwarding: bool = False
    empty_passwords: bool = False
    client_alive_interval: int = 300
    client_alive_count_max: int = 2


@dataclass
class SSHUser:
    username: str
    groups: Set[str]
    root: bool = False
    locked: bool = False
    public_key_configured: bool = False


@dataclass
class SSHAttempt:
    username: str
    method: AuthenticationMethod
    successful_credential: bool = True
    attempts: int = 1


class SSHSecurityModel:
    """Evaluate SSH access without opening a real network listener."""

    def __init__(self, config: SSHConfig, users: Iterable[SSHUser]) -> None:
        self.config = config
        self.users = {user.username: user for user in users}

    def is_allowed(self, attempt: SSHAttempt) -> Tuple[bool, str]:
        user = self.users.get(attempt.username)

        if user is None:
            return False, "Unknown account."

        if user.locked:
            return False, "Account is locked."

        if user.root and self.config.permit_root_login != "yes":
            if self.config.permit_root_login == "prohibit-password":
                if attempt.method == AuthenticationMethod.PASSWORD:
                    return False, "Direct root password authentication is prohibited."
            else:
                return False, "Direct root SSH login is disabled."

        if self.config.allow_users and user.username not in self.config.allow_users:
            return False, "Account is not in the SSH AllowUsers policy."

        if self.config.allow_groups and not (
            user.groups & self.config.allow_groups
        ):
            return False, "User belongs to none of the allowed SSH groups."

        if attempt.attempts > self.config.max_auth_tries:
            return False, "Maximum authentication attempts exceeded."

        if attempt.method == AuthenticationMethod.PASSWORD:
            if not self.config.password_authentication:
                return False, "Password authentication is disabled."
            if self.config.empty_passwords:
                return False, "Empty passwords are explicitly unsafe."

        if attempt.method == AuthenticationMethod.PUBLIC_KEY:
            if not self.config.pubkey_authentication:
                return False, "Public-key authentication is disabled."
            if not user.public_key_configured:
                return False, "No public key is configured for this account."

        if not attempt.successful_credential:
            return False, "Credential verification failed."

        return True, "SSH authentication and access policy permit the connection."

    def audit(self) -> List[Finding]:
        findings: List[Finding] = []

        if self.config.permit_root_login == "yes":
            findings.append(
                Finding(
                    "SSH",
                    Severity.CRITICAL,
                    "Direct root login enabled",
                    "The SSH daemon permits direct remote root authentication.",
                    "Set PermitRootLogin to no and administer through an authorized account with sudo.",
                )
            )

        if self.config.password_authentication:
            findings.append(
                Finding(
                    "SSH",
                    Severity.HIGH,
                    "Password authentication enabled",
                    "SSH accepts passwords rather than requiring stronger configured credentials.",
                    "Prefer public-key authentication and disable password authentication after key access is verified.",
                )
            )

        if not self.config.pubkey_authentication:
            findings.append(
                Finding(
                    "SSH",
                    Severity.HIGH,
                    "Public-key authentication disabled",
                    "The stronger SSH authentication mechanism is unavailable.",
                    "Enable public-key authentication and deploy keys securely.",
                )
            )

        if self.config.max_auth_tries > 4:
            findings.append(
                Finding(
                    "SSH",
                    Severity.MEDIUM,
                    "Authentication retry limit is high",
                    f"MaxAuthTries is {self.config.max_auth_tries}.",
                    "Use a low retry limit appropriate for the environment.",
                )
            )

        if self.config.x11_forwarding:
            findings.append(
                Finding(
                    "SSH",
                    Severity.MEDIUM,
                    "X11 forwarding enabled",
                    "SSH sessions can request X11 forwarding.",
                    "Disable X11 forwarding unless an explicit operational requirement exists.",
                )
            )

        if self.config.agent_forwarding:
            findings.append(
                Finding(
                    "SSH",
                    Severity.MEDIUM,
                    "Agent forwarding enabled",
                    "SSH agent credentials may be exposed through compromised intermediate hosts.",
                    "Disable agent forwarding unless the connection path requires it.",
                )
            )

        if self.config.tcp_forwarding:
            findings.append(
                Finding(
                    "SSH",
                    Severity.MEDIUM,
                    "TCP forwarding enabled",
                    "SSH users can potentially create tunnels through the host.",
                    "Disable forwarding when tunneling is not required.",
                )
            )

        return findings


# ---------------------------------------------------------------------------
# sudo
# ---------------------------------------------------------------------------

@dataclass
class SudoRule:
    users: Set[str]
    commands: Set[str]
    run_as: str = "root"
    require_password: bool = True
    noexec: bool = False

    def matches(self, username: str, command: str) -> bool:
        user_match = username in self.users or "ALL" in self.users
        command_match = command in self.commands or "ALL" in self.commands
        return user_match and command_match


class SudoPolicy:
    """Model least-privilege sudo authorization."""

    def __init__(self, rules: Iterable[SudoRule]) -> None:
        self.rules = list(rules)

    def authorize(self, username: str, command: str) -> Tuple[bool, str]:
        for rule in self.rules:
            if rule.matches(username, command):
                return True, (
                    f"Authorized as {rule.run_as}; "
                    f"password_required={rule.require_password}; "
                    f"noexec={rule.noexec}"
                )
        return False, "No sudo rule authorizes this user-command combination."

    def audit(self) -> List[Finding]:
        findings: List[Finding] = []

        for rule in self.rules:
            if "ALL" in rule.users and "ALL" in rule.commands:
                findings.append(
                    Finding(
                        "sudo",
                        Severity.CRITICAL,
                        "Unrestricted sudo rule",
                        "A rule grants all users unrestricted command execution.",
                        "Replace ALL-to-ALL authorization with explicit users, groups, and commands.",
                    )
                )
            elif "ALL" in rule.commands:
                findings.append(
                    Finding(
                        "sudo",
                        Severity.HIGH,
                        "Broad command authorization",
                        f"Users {sorted(rule.users)} can execute every command.",
                        "Restrict sudo to the smallest operational command set.",
                    )
                )

            if not rule.require_password:
                findings.append(
                    Finding(
                        "sudo",
                        Severity.MEDIUM,
                        "Passwordless sudo rule",
                        f"Users {sorted(rule.users)} can execute {sorted(rule.commands)} without a password.",
                        "Use NOPASSWD only for tightly controlled automation where justified.",
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# Unix permissions
# ---------------------------------------------------------------------------

@dataclass
class FileObject:
    path: str
    owner: str
    group: str
    mode: int
    is_directory: bool = False


@dataclass
class AccessRequest:
    username: str
    groups: Set[str]
    action: str


class PermissionEngine:
    """Evaluate simplified Unix owner/group/other permission semantics."""

    ACTION_BITS = {
        "read": 4,
        "write": 2,
        "execute": 1,
    }

    def __init__(self, objects: Iterable[FileObject]) -> None:
        self.objects = {obj.path: obj for obj in objects}

    @staticmethod
    def _class_bits(mode: int, owner: bool, group: bool) -> int:
        if owner:
            return (mode >> 6) & 0b111
        if group:
            return (mode >> 3) & 0b111
        return mode & 0b111

    def can_access(self, path: str, request: AccessRequest) -> Tuple[bool, str]:
        obj = self.objects.get(path)
        if obj is None:
            return False, "Path does not exist in the security model."

        if request.action not in self.ACTION_BITS:
            return False, "Unsupported access action."

        if request.username == obj.owner:
            bits = self._class_bits(obj.mode, True, False)
            source = "owner"
        elif obj.group in request.groups:
            bits = self._class_bits(obj.mode, False, True)
            source = "group"
        else:
            bits = self._class_bits(obj.mode, False, False)
            source = "other"

        required = self.ACTION_BITS[request.action]
        allowed = (bits & required) == required

        if allowed:
            return True, f"Allowed by {source} permission bits."
        return False, f"Denied by {source} permission bits."

    def audit(self) -> List[Finding]:
        findings: List[Finding] = []

        for obj in self.objects.values():
            mode = obj.mode & 0o777

            if mode & 0o002:
                findings.append(
                    Finding(
                        "Permissions",
                        Severity.HIGH,
                        "World-writable object",
                        f"{obj.path} has mode {mode:04o}.",
                        "Remove unnecessary write permission for other users.",
                    )
                )

            if not obj.is_directory and mode & 0o004:
                findings.append(
                    Finding(
                        "Permissions",
                        Severity.MEDIUM,
                        "World-readable file",
                        f"{obj.path} is readable by other users.",
                        "Restrict sensitive files to the required owner or group.",
                    )
                )

            if mode & 0o4000:
                findings.append(
                    Finding(
                        "Permissions",
                        Severity.HIGH,
                        "Setuid bit detected",
                        f"{obj.path} has the setuid bit enabled.",
                        "Verify that the privileged executable is required and trusted.",
                    )
                )

            if mode & 0o2000 and obj.is_directory:
                findings.append(
                    Finding(
                        "Permissions",
                        Severity.LOW,
                        "Setgid directory",
                        f"{obj.path} uses setgid inheritance.",
                        "Verify that group inheritance matches the intended collaboration boundary.",
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# Secure configuration
# ---------------------------------------------------------------------------

@dataclass
class SecurityConfiguration:
    firewall_enabled: bool
    automatic_security_updates: bool
    audit_logging: bool
    time_synchronization: bool
    core_dumps_restricted: bool
    kernel_module_loading_restricted: bool
    file_integrity_monitoring: bool
    secure_boot: bool = False


class ConfigurationAuditor:
    def __init__(self, config: SecurityConfiguration) -> None:
        self.config = config

    def audit(self) -> List[Finding]:
        findings: List[Finding] = []

        checks = [
            (
                self.config.firewall_enabled,
                "Firewall disabled",
                Severity.HIGH,
                "Host-level network exposure is not constrained by a local firewall.",
                "Enable a host firewall and permit only required traffic.",
            ),
            (
                self.config.automatic_security_updates,
                "Automatic security updates disabled",
                Severity.MEDIUM,
                "Security fixes may remain unapplied longer than intended.",
                "Enable controlled automatic security updates or an equivalent patch-management process.",
            ),
            (
                self.config.audit_logging,
                "Security audit logging disabled",
                Severity.HIGH,
                "Important authentication and authorization events may not be available for investigation.",
                "Enable appropriate audit and system logging with controlled retention.",
            ),
            (
                self.config.time_synchronization,
                "Time synchronization disabled",
                Severity.MEDIUM,
                "Inconsistent system clocks can make authentication and incident timelines unreliable.",
                "Use a trusted time synchronization mechanism.",
            ),
            (
                self.config.core_dumps_restricted,
                "Core dumps not restricted",
                Severity.MEDIUM,
                "Crash artifacts can expose sensitive process memory.",
                "Restrict core dumps according to application and incident-response requirements.",
            ),
            (
                self.config.kernel_module_loading_restricted,
                "Kernel module loading unrestricted",
                Severity.MEDIUM,
                "Uncontrolled kernel module loading increases the privileged attack surface.",
                "Restrict module loading where operationally appropriate.",
            ),
            (
                self.config.file_integrity_monitoring,
                "File integrity monitoring disabled",
                Severity.MEDIUM,
                "Unexpected changes to critical files may go undetected.",
                "Monitor security-sensitive paths for unauthorized modifications.",
            ),
            (
                self.config.secure_boot,
                "Secure Boot unavailable or disabled",
                Severity.LOW,
                "The platform is not using firmware-level boot-chain verification.",
                "Enable Secure Boot where hardware, operating system, and operational requirements support it.",
            ),
        ]

        for enabled, title, severity, detail, recommendation in checks:
            if not enabled:
                findings.append(
                    Finding(
                        "Secure configuration",
                        severity,
                        title,
                        detail,
                        recommendation,
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# Service minimization
# ---------------------------------------------------------------------------

@dataclass
class Service:
    name: str
    enabled_at_boot: bool
    listening_ports: Set[int]
    business_required: bool
    remotely_reachable: bool


class ServiceMinimizer:
    """Identify unnecessary services and network exposure."""

    def __init__(self, services: Iterable[Service]) -> None:
        self.services = list(services)

    def audit(self) -> List[Finding]:
        findings: List[Finding] = []

        for service in self.services:
            if not service.business_required and service.enabled_at_boot:
                findings.append(
                    Finding(
                        "Services",
                        Severity.HIGH,
                        "Unnecessary enabled service",
                        f"{service.name} starts automatically but is not business-required.",
                        "Disable and remove the service when it is not needed.",
                    )
                )

            if not service.business_required and service.listening_ports:
                ports = ", ".join(str(port) for port in sorted(service.listening_ports))
                findings.append(
                    Finding(
                        "Services",
                        Severity.HIGH,
                        "Unnecessary network listener",
                        f"{service.name} listens on ports {ports}.",
                        "Stop the service or restrict the listener to required interfaces and networks.",
                    )
                )

            if service.remotely_reachable and service.listening_ports:
                findings.append(
                    Finding(
                        "Services",
                        Severity.MEDIUM,
                        "Remote service exposure",
                        f"{service.name} has remotely reachable listeners: {sorted(service.listening_ports)}.",
                        "Confirm that each exposed service is necessary and explicitly authorized.",
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# Combined host governance
# ---------------------------------------------------------------------------

class LinuxSecurityAssessment:
    def __init__(
        self,
        ssh: SSHSecurityModel,
        sudo: SudoPolicy,
        permissions: PermissionEngine,
        configuration: ConfigurationAuditor,
        services: ServiceMinimizer,
    ) -> None:
        self.ssh = ssh
        self.sudo = sudo
        self.permissions = permissions
        self.configuration = configuration
        self.services = services

    def findings(self) -> List[Finding]:
        return (
            self.ssh.audit()
            + self.sudo.audit()
            + self.permissions.audit()
            + self.configuration.audit()
            + self.services.audit()
        )

    def score(self) -> int:
        penalties = {
            Severity.INFO: 0,
            Severity.LOW: 2,
            Severity.MEDIUM: 5,
            Severity.HIGH: 10,
            Severity.CRITICAL: 20,
        }
        return max(
            0,
            100 - sum(penalties[finding.severity] for finding in self.findings()),
        )

    def report(self) -> None:
        findings = self.findings()
        print("\n=== Linux Security Assessment ===")
        print(f"Security posture score: {self.score()}/100")
        print(f"Findings: {len(findings)}")

        if not findings:
            print("No policy violations detected.")
            return

        for finding in findings:
            print()
            print(finding.display())


# ---------------------------------------------------------------------------
# Configuration and scenario
# ---------------------------------------------------------------------------

def build_demo_assessment() -> LinuxSecurityAssessment:
    ssh_config = SSHConfig(
        permit_root_login="no",
        password_authentication=False,
        pubkey_authentication=True,
        allow_users={"alice", "opsadmin"},
        allow_groups={"linux-admins"},
        max_auth_tries=3,
        x11_forwarding=False,
        agent_forwarding=False,
        tcp_forwarding=False,
        empty_passwords=False,
        client_alive_interval=300,
        client_alive_count_max=2,
    )

    ssh_users = [
        SSHUser(
            username="alice",
            groups={"developers"},
            public_key_configured=True,
        ),
        SSHUser(
            username="opsadmin",
            groups={"linux-admins"},
            public_key_configured=True,
        ),
        SSHUser(
            username="legacy",
            groups={"developers"},
            public_key_configured=False,
        ),
        SSHUser(
            username="root",
            groups={"root"},
            root=True,
            public_key_configured=True,
        ),
    ]

    ssh = SSHSecurityModel(ssh_config, ssh_users)

    sudo = SudoPolicy(
        [
            SudoRule(
                users={"opsadmin"},
                commands={
                    "/usr/bin/systemctl restart nginx",
                    "/usr/bin/systemctl status nginx",
                },
                run_as="root",
                require_password=True,
                noexec=True,
            ),
            SudoRule(
                users={"alice"},
                commands={"/usr/bin/journalctl"},
                run_as="root",
                require_password=True,
                noexec=True,
            ),
        ]
    )

    permissions = PermissionEngine(
        [
            FileObject(
                path="/etc/ssh/sshd_config",
                owner="root",
                group="root",
                mode=0o600,
            ),
            FileObject(
                path="/etc/shadow",
                owner="root",
                group="shadow",
                mode=0o640,
            ),
            FileObject(
                path="/srv/application",
                owner="deploy",
                group="app",
                mode=0o750,
                is_directory=True,
            ),
            FileObject(
                path="/tmp/shared-upload",
                owner="deploy",
                group="app",
                mode=0o777,
            ),
            FileObject(
                path="/usr/bin/authorized-helper",
                owner="root",
                group="root",
                mode=0o4755,
            ),
        ]
    )

    configuration = ConfigurationAuditor(
        SecurityConfiguration(
            firewall_enabled=True,
            automatic_security_updates=True,
            audit_logging=True,
            time_synchronization=True,
            core_dumps_restricted=True,
            kernel_module_loading_restricted=True,
            file_integrity_monitoring=False,
            secure_boot=True,
        )
    )

    services = ServiceMinimizer(
        [
            Service(
                name="sshd",
                enabled_at_boot=True,
                listening_ports={22},
                business_required=True,
                remotely_reachable=True,
            ),
            Service(
                name="nginx",
                enabled_at_boot=True,
                listening_ports={443},
                business_required=True,
                remotely_reachable=True,
            ),
            Service(
                name="telnet",
                enabled_at_boot=True,
                listening_ports={23},
                business_required=False,
                remotely_reachable=True,
            ),
            Service(
                name="cups",
                enabled_at_boot=True,
                listening_ports={631},
                business_required=False,
                remotely_reachable=False,
            ),
        ]
    )

    return LinuxSecurityAssessment(
        ssh=ssh,
        sudo=sudo,
        permissions=permissions,
        configuration=configuration,
        services=services,
    )


# ---------------------------------------------------------------------------
# Demonstrations
# ---------------------------------------------------------------------------

def demonstrate_ssh(assessment: LinuxSecurityAssessment) -> None:
    print("\n=== SSH Access Decisions ===")

    attempts = [
        SSHAttempt("opsadmin", AuthenticationMethod.PUBLIC_KEY),
        SSHAttempt("legacy", AuthenticationMethod.PASSWORD),
        SSHAttempt("root", AuthenticationMethod.PUBLIC_KEY),
        SSHAttempt("alice", AuthenticationMethod.PUBLIC_KEY),
        SSHAttempt("alice", AuthenticationMethod.PUBLIC_KEY, attempts=5),
    ]

    for attempt in attempts:
        allowed, reason = assessment.ssh.is_allowed(attempt)
        state = "ALLOW" if allowed else "DENY"
        print(
            f"{state:<5} user={attempt.username:<10} "
            f"method={attempt.method.value:<10} reason={reason}"
        )


def demonstrate_sudo(assessment: LinuxSecurityAssessment) -> None:
    print("\n=== sudo Authorization ===")

    requests = [
        ("opsadmin", "/usr/bin/systemctl restart nginx"),
        ("opsadmin", "/bin/bash"),
        ("alice", "/usr/bin/journalctl"),
        ("alice", "/usr/bin/systemctl restart nginx"),
    ]

    for username, command in requests:
        allowed, reason = assessment.sudo.authorize(username, command)
        state = "ALLOW" if allowed else "DENY"
        print(f"{state:<5} {username:<10} sudo {command} -> {reason}")


def demonstrate_permissions(assessment: LinuxSecurityAssessment) -> None:
    print("\n=== Unix Permission Decisions ===")

    requests = [
        ("/etc/ssh/sshd_config", AccessRequest("alice", {"developers"}, "read")),
        ("/etc/ssh/sshd_config", AccessRequest("root", {"root"}, "read")),
        ("/etc/shadow", AccessRequest("alice", {"developers"}, "read")),
        ("/srv/application", AccessRequest("deploy", {"app"}, "execute")),
        ("/srv/application", AccessRequest("alice", {"developers"}, "execute")),
        ("/tmp/shared-upload", AccessRequest("alice", {"developers"}, "write")),
    ]

    for path, request in requests:
        allowed, reason = assessment.permissions.can_access(path, request)
        state = "ALLOW" if allowed else "DENY"
        print(
            f"{state:<5} user={request.username:<10} "
            f"action={request.action:<7} path={path} -> {reason}"
        )


def demonstrate_policy_reasoning() -> None:
    print("\n=== Security Design Relationships ===")
    print(
        "SSH controls who can establish a remote administrative session. "
        "It does not by itself grant root privileges."
    )
    print(
        "sudo controls privileged command execution after authentication. "
        "A successful SSH login does not imply unrestricted sudo access."
    )
    print(
        "Filesystem permissions independently control access to files and directories. "
        "sudo policy and file permissions therefore represent different authorization layers."
    )
    print(
        "Secure configuration reduces exploitable host behavior, while service minimization "
        "reduces the number of active components that require security maintenance."
    )


def run_edge_case_checks(assessment: LinuxSecurityAssessment) -> None:
    print("\n=== Edge Cases ===")

    unknown = SSHAttempt("does-not-exist", AuthenticationMethod.PUBLIC_KEY)
    allowed, reason = assessment.ssh.is_allowed(unknown)
    print(f"Unknown SSH account: {'ALLOW' if allowed else 'DENY'} -> {reason}")

    allowed, reason = assessment.permissions.can_access(
        "/does/not/exist",
        AccessRequest("alice", {"developers"}, "read"),
    )
    print(f"Missing path: {'ALLOW' if allowed else 'DENY'} -> {reason}")

    allowed, reason = assessment.sudo.authorize(
        "alice",
        "/bin/bash",
    )
    print(f"Unlisted privileged command: {'ALLOW' if allowed else 'DENY'} -> {reason}")


def main() -> None:
    assessment = build_demo_assessment()

    print("Linux Security Configuration and Governance Lab")
    print("The program performs policy simulation only; it does not change the host.")

    demonstrate_ssh(assessment)
    demonstrate_sudo(assessment)
    demonstrate_permissions(assessment)
    run_edge_case_checks(assessment)
    demonstrate_policy_reasoning()
    assessment.report()

    print("\n=== Hardening Priorities ===")
    print(
        "Prioritize elimination of unnecessary network services, "
        "tight sudo command authorization, protection of sensitive files, "
        "strong SSH authentication, and continuous security configuration auditing."
    )


if __name__ == "__main__":
    main()
