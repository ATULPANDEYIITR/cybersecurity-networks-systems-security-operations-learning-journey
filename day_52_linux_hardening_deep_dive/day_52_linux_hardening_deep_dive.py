#!/usr/bin/env python3
"""
Linux Hardening Deep Dive
SSH, sudo, filesystem permissions, kernel controls, and auditing.

This script is a safe local hardening-audit simulator. It can inspect a Linux
host in read-only mode and evaluate selected security controls without making
system changes.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Optional


@dataclass
class Finding:
    category: str
    control: str
    status: str
    severity: str
    evidence: str
    recommendation: str


class CommandError(RuntimeError):
    pass


def run_command(command: list[str], timeout: int = 5) -> str:
    """Run a read-only command and return stdout."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CommandError(str(exc)) from exc

    if result.returncode != 0:
        raise CommandError(result.stderr.strip() or f"exit code {result.returncode}")

    return result.stdout.strip()


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def parse_mode(mode: str) -> int:
    if not re.fullmatch(r"[0-7]{3,4}", mode):
        raise ValueError(f"Invalid permission mode: {mode}")
    return int(mode, 8)


class LinuxHardeningAuditor:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(
        self,
        category: str,
        control: str,
        status: str,
        severity: str,
        evidence: str,
        recommendation: str,
    ) -> None:
        self.findings.append(
            Finding(
                category,
                control,
                status,
                severity,
                evidence,
                recommendation,
            )
        )

    def audit_ssh(self) -> None:
        path = Path("/etc/ssh/sshd_config")
        content = read_text(path)

        if content is None:
            self.add(
                "SSH",
                "sshd_config readability",
                "UNKNOWN",
                "medium",
                f"Unable to read {path}",
                "Run the audit with sufficient read permissions.",
            )
            return

        effective: dict[str, str] = {}
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(None, 1)
            if len(parts) == 2:
                effective[parts[0].lower()] = parts[1].strip()

        checks = [
            (
                "PermitRootLogin",
                lambda v: v.lower() in {"no", "prohibit-password"},
                "Prefer PermitRootLogin no unless controlled administrative access is explicitly required.",
            ),
            (
                "PasswordAuthentication",
                lambda v: v.lower() == "no",
                "Prefer key-based authentication and disable password authentication where operationally appropriate.",
            ),
            (
                "PermitEmptyPasswords",
                lambda v: v.lower() == "no",
                "Set PermitEmptyPasswords no.",
            ),
            (
                "X11Forwarding",
                lambda v: v.lower() == "no",
                "Disable X11 forwarding when it is not required.",
            ),
        ]

        for directive, predicate, recommendation in checks:
            value = effective.get(directive.lower())

            if value is None:
                self.add(
                    "SSH",
                    directive,
                    "REVIEW",
                    "medium",
                    "Directive is not explicitly present in sshd_config.",
                    recommendation,
                )
            elif predicate(value):
                self.add(
                    "SSH",
                    directive,
                    "PASS",
                    "info",
                    f"{directive}={value}",
                    "No immediate change identified.",
                )
            else:
                self.add(
                    "SSH",
                    directive,
                    "FAIL",
                    "high",
                    f"{directive}={value}",
                    recommendation,
                )

    def audit_sudo(self) -> None:
        sudoers = Path("/etc/sudoers")
        content = read_text(sudoers)

        if content is None:
            self.add(
                "sudo",
                "sudoers readability",
                "UNKNOWN",
                "medium",
                f"Unable to read {sudoers}",
                "Run the audit with sufficient read permissions.",
            )
            return

        dangerous = []
        for number, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if "NOPASSWD:" in line.upper():
                dangerous.append(f"line {number}: {line}")

            if re.search(r"\bALL\s*=\s*\(ALL(?:,\s*[^)]*)?\)\s*ALL\b", line):
                self.add(
                    "sudo",
                    "broad administrative rule",
                    "REVIEW",
                    "high",
                    f"line {number}: {line}",
                    "Use narrowly scoped commands and groups instead of unrestricted administrative rules.",
                )

        if dangerous:
            self.add(
                "sudo",
                "NOPASSWD rules",
                "REVIEW",
                "medium",
                "; ".join(dangerous),
                "Ensure passwordless elevation is restricted to operationally justified commands.",
            )
        else:
            self.add(
                "sudo",
                "NOPASSWD rules",
                "PASS",
                "info",
                "No NOPASSWD rule found in /etc/sudoers.",
                "Continue reviewing included sudoers files and command-specific privileges.",
            )

    def audit_filesystem(self) -> None:
        targets = [
            (Path("/etc/passwd"), 0o644, False),
            (Path("/etc/group"), 0o644, False),
            (Path("/etc/shadow"), 0o640, True),
            (Path("/etc/gshadow"), 0o640, True),
            (Path("/etc/sudoers"), 0o440, True),
        ]

        for path, expected_max, sensitive in targets:
            try:
                mode = stat.S_IMODE(path.stat().st_mode)
            except (OSError, PermissionError) as exc:
                self.add(
                    "Filesystem permissions",
                    str(path),
                    "UNKNOWN",
                    "medium",
                    str(exc),
                    "Verify ownership and permissions manually.",
                )
                continue

            excessive = mode & 0o007
            if sensitive and excessive:
                self.add(
                    "Filesystem permissions",
                    str(path),
                    "FAIL",
                    "high",
                    f"Mode {mode:04o}; world permissions are present.",
                    f"Restrict {path} to the minimum required owner/group permissions.",
                )
            elif mode & ~expected_max:
                self.add(
                    "Filesystem permissions",
                    str(path),
                    "REVIEW",
                    "medium",
                    f"Mode {mode:04o}; expected maximum baseline is {expected_max:04o}.",
                    "Verify that the additional permissions are intentional.",
                )
            else:
                self.add(
                    "Filesystem permissions",
                    str(path),
                    "PASS",
                    "info",
                    f"Mode {mode:04o}",
                    "No excessive permissions detected against this baseline.",
                )

    def audit_kernel(self) -> None:
        controls = {
            "kernel.randomize_va_space": ("2", "/proc/sys/kernel/randomize_va_space"),
            "fs.protected_hardlinks": ("1", "/proc/sys/fs/protected_hardlinks"),
            "fs.protected_symlinks": ("1", "/proc/sys/fs/protected_symlinks"),
        }

        for name, (expected, proc_path) in controls.items():
            value = read_text(Path(proc_path))

            if value is None:
                self.add(
                    "Kernel controls",
                    name,
                    "UNKNOWN",
                    "medium",
                    f"Unable to read {proc_path}",
                    "Verify the kernel control manually.",
                )
                continue

            actual = value.strip()
            if actual == expected:
                self.add(
                    "Kernel controls",
                    name,
                    "PASS",
                    "info",
                    f"{actual} == expected {expected}",
                    "No immediate change identified.",
                )
            else:
                self.add(
                    "Kernel controls",
                    name,
                    "FAIL",
                    "high",
                    f"{actual} != expected {expected}",
                    f"Evaluate setting {name} to {expected} through the distribution's supported configuration mechanism.",
                )

    def audit_auditing(self) -> None:
        auditctl = Path("/sbin/auditctl")

        if not auditctl.exists():
            self.add(
                "Auditing",
                "audit subsystem",
                "REVIEW",
                "medium",
                "auditctl was not found at /sbin/auditctl.",
                "Verify whether Linux auditing is provided through another supported installation path.",
            )
            return

        try:
            output = run_command([str(auditctl), "-s"])
        except CommandError as exc:
            self.add(
                "Auditing",
                "audit subsystem",
                "UNKNOWN",
                "medium",
                str(exc),
                "Run auditctl -s with appropriate privileges.",
            )
            return

        enabled_match = re.search(r"enabled\s+(\d+)", output)
        if enabled_match and enabled_match.group(1) in {"1", "2"}:
            self.add(
                "Auditing",
                "audit subsystem enabled",
                "PASS",
                "info",
                f"enabled={enabled_match.group(1)}",
                "Keep audit configuration persistent and monitored.",
            )
        else:
            self.add(
                "Auditing",
                "audit subsystem enabled",
                "FAIL",
                "high",
                output,
                "Enable and persist the Linux audit subsystem according to the distribution's supported configuration.",
            )

    def audit(self) -> list[Finding]:
        self.audit_ssh()
        self.audit_sudo()
        self.audit_filesystem()
        self.audit_kernel()
        self.audit_auditing()
        return self.findings


def print_report(findings: list[Finding]) -> None:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.status] = counts.get(finding.status, 0) + 1

    print(f"Platform: {platform.platform()}")
    print(f"Effective UID: {os.geteuid() if hasattr(os, 'geteuid') else 'unknown'}")
    print(f"Findings: {len(findings)}")
    print(
        "Status counts: "
        + ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
    )
    print()

    for finding in findings:
        print(
            f"[{finding.status:<7}] "
            f"{finding.category:<24} "
            f"{finding.control}"
        )
        print(f"  Severity: {finding.severity}")
        print(f"  Evidence: {finding.evidence}")
        print(f"  Action:   {finding.recommendation}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Linux hardening audit."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit findings as JSON",
    )
    args = parser.parse_args()

    if os.name != "posix":
        raise SystemExit("This audit requires a Linux/POSIX environment.")

    auditor = LinuxHardeningAuditor()
    findings = auditor.audit()

    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    else:
        print_report(findings)

    return 1 if any(item.status == "FAIL" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
