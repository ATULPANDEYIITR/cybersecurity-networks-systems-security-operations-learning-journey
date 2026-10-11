"""
Windows Fundamentals: Architecture, Users, Groups, Services, Registry, and Filesystem.

Self-contained Windows administration and security learning laboratory.
Runs on Windows and supports a safe demonstration mode on other platforms.
Uses only the Python standard library.

Examples:
    python windows_fundamentals.py
    python windows_fundamentals.py --inspect
    python windows_fundamentals.py --filesystem-demo
    python windows_fundamentals.py --security-audit
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def heading(title: str) -> None:
    print(f"\n{'=' * 76}\n{title}\n{'=' * 76}")


def run_command(
    arguments: list[str],
    timeout: int = 15,
) -> tuple[int, str, str]:
    """Run a command without invoking a shell or interpreting shell metacharacters."""
    try:
        result = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, "", str(exc)


def is_windows() -> bool:
    return os.name == "nt"


def windows_architecture() -> dict[str, str]:
    """
    Distinguish process architecture from operating-system architecture.
    A 32-bit process can execute on a 64-bit Windows installation.
    """
    result = {
        "operating_system": platform.system(),
        "os_description": platform.platform(),
        "machine": platform.machine(),
        "python_process_architecture": platform.architecture()[0],
        "python_version": platform.python_version(),
    }

    if not is_windows():
        result["note"] = "Windows-specific APIs are unavailable on this platform."
        return result

    try:
        version = sys.getwindowsversion()
        result["windows_version"] = (
            f"{version.major}.{version.minor}.{version.build}"
        )
        result["windows_platform"] = str(version.platform)
    except AttributeError:
        result["windows_version"] = "Unavailable"

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.IsWow64Process.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        kernel32.IsWow64Process.restype = ctypes.c_int

        wow64 = ctypes.c_int(0)
        process_handle = kernel32.GetCurrentProcess()

        if kernel32.IsWow64Process(process_handle, ctypes.byref(wow64)):
            result["process_is_wow64"] = str(bool(wow64.value))
    except (AttributeError, OSError):
        result["process_is_wow64"] = "Unavailable"

    return result


def collect_identity() -> dict[str, Any]:
    """Inspect the current identity without assuming the process is elevated."""
    identity: dict[str, Any] = {
        "username": os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
        "user_domain": os.environ.get("USERDOMAIN", ""),
        "home_directory": str(Path.home()),
        "is_windows": is_windows(),
    }

    if not is_windows():
        identity["uid"] = getattr(os, "getuid", lambda: None)()
        identity["gid"] = getattr(os, "getgid", lambda: None)()
        return identity

    code, output, error = run_command(
        ["whoami", "/user", "/fo", "list", "/nh"]
    )
    identity["user_sid_command_succeeded"] = code == 0
    identity["user_sid_output"] = output if code == 0 else error

    code, output, error = run_command(["whoami", "/groups", "/fo", "csv"])
    identity["group_memberships_command_succeeded"] = code == 0
    identity["group_memberships"] = (
        output.splitlines() if code == 0 else [error]
    )

    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.IsUserAnAdmin.restype = ctypes.c_int
        identity["process_has_administrative_token"] = bool(
            shell32.IsUserAnAdmin()
        )
    except (AttributeError, OSError):
        identity["process_has_administrative_token"] = None

    return identity


def inspect_local_accounts() -> dict[str, Any]:
    """
    Query local accounts and groups using Windows command-line tools.
    A domain-managed account inventory requires appropriate domain tooling
    and permissions; local account results are not a complete AD inventory.
    """
    if not is_windows():
        return {"available": False, "reason": "Windows only"}

    commands = {
        "local_users": ["net", "user"],
        "local_groups": ["net", "localgroup"],
    }

    inventory: dict[str, Any] = {"available": True}

    for name, arguments in commands.items():
        code, output, error = run_command(arguments)
        inventory[name] = {
            "return_code": code,
            "output": output,
            "error": error,
        }

    return inventory


@dataclass(frozen=True)
class ServiceRecord:
    name: str
    display_name: str
    state: str
    start_type: str
    service_type: str


def inspect_services(limit: int = 25) -> list[dict[str, str]]:
    """
    Read service configuration and state.
    Inspection does not start, stop, reconfigure, or delete services.
    """
    if not is_windows():
        return []

    code, output, error = run_command(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "Get-CimInstance Win32_Service | "
                "Select-Object Name,DisplayName,State,StartMode,ServiceType | "
                "ConvertTo-Json -Depth 3 -Compress"
            ),
        ],
        timeout=30,
    )

    if code != 0:
        print(f"Service query failed: {error}")
        return []

    try:
        records = json.loads(output)
    except json.JSONDecodeError:
        print("Service query returned invalid JSON.")
        return []

    if isinstance(records, dict):
        records = [records]

    services = [
        ServiceRecord(
            name=str(item.get("Name", "")),
            display_name=str(item.get("DisplayName", "")),
            state=str(item.get("State", "")),
            start_type=str(item.get("StartMode", "")),
            service_type=str(item.get("ServiceType", "")),
        )
        for item in records
    ]

    services.sort(key=lambda item: (item.state != "Running", item.name.lower()))

    return [asdict(service) for service in services[:limit]]


def inspect_service(name: str) -> dict[str, Any]:
    """Inspect a specific service by its service name."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", name):
        raise ValueError("Invalid service name.")

    if not is_windows():
        return {"available": False, "reason": "Windows only"}

    code, output, error = run_command(["sc.exe", "queryex", name])
    config_code, config_output, config_error = run_command(
        ["sc.exe", "qc", name]
    )

    return {
        "service_name": name,
        "query_return_code": code,
        "query": output,
        "query_error": error,
        "config_return_code": config_code,
        "configuration": config_output,
        "configuration_error": config_error,
    }


def inspect_registry_read_only() -> dict[str, Any]:
    """
    Read a small set of diagnostic registry values.
    Registry writes are deliberately excluded from this inspection.
    """
    if not is_windows():
        return {"available": False, "reason": "Windows only"}

    import winreg

    queries = [
        (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            ["ProductName", "DisplayVersion", "CurrentBuild"],
        ),
        (
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            ["PROCESSOR_ARCHITECTURE", "OS"],
        ),
    ]

    results: dict[str, Any] = {}

    for subkey, value_names in queries:
        key_results: dict[str, Any] = {}

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                subkey,
                0,
                winreg.KEY_READ,
            ) as key:
                for value_name in value_names:
                    try:
                        value, value_type = winreg.QueryValueEx(
                            key, value_name
                        )
                        key_results[value_name] = {
                            "value": value,
                            "registry_type": value_type,
                        }
                    except FileNotFoundError:
                        key_results[value_name] = "Value not present"
        except OSError as exc:
            key_results["error"] = str(exc)

        results[subkey] = key_results

    return results


def describe_filesystem_paths() -> dict[str, Any]:
    """Describe standard Windows filesystem locations and their roles."""
    candidates = {
        "system_root": os.environ.get("SystemRoot"),
        "windows_directory": os.environ.get("WINDIR"),
        "program_files": os.environ.get("ProgramFiles"),
        "program_files_x86": os.environ.get("ProgramFiles(x86)"),
        "program_data": os.environ.get("ProgramData"),
        "user_profile": os.environ.get("USERPROFILE"),
        "local_app_data": os.environ.get("LOCALAPPDATA"),
        "roaming_app_data": os.environ.get("APPDATA"),
        "temporary_directory": tempfile.gettempdir(),
    }

    descriptions: dict[str, Any] = {}

    for name, value in candidates.items():
        if value:
            path = Path(value)
            descriptions[name] = {
                "path": str(path),
                "exists": path.exists(),
                "is_directory": path.is_dir() if path.exists() else False,
            }
        else:
            descriptions[name] = {"available": False}

    return descriptions


def filesystem_demo() -> dict[str, Any]:
    """
    Create an isolated temporary directory, exercise file operations,
    and remove the test data automatically.
    """
    results: dict[str, Any] = {}

    with tempfile.TemporaryDirectory(prefix="windows-fundamentals-") as root:
        base = Path(root)
        documents = base / "Documents"
        logs = base / "Logs"

        documents.mkdir()
        logs.mkdir()

        config_path = documents / "application.json"
        log_path = logs / "audit.log"

        config = {
            "application": "inventory-console",
            "environment": "training",
            "logging_enabled": True,
        }

        config_path.write_text(
            json.dumps(config, indent=2),
            encoding="utf-8",
        )
        log_path.write_text(
            "event=application_started\n"
            "event=configuration_loaded\n",
            encoding="utf-8",
        )

        loaded_config = json.loads(config_path.read_text(encoding="utf-8"))

        results["temporary_root"] = str(base)
        results["configuration"] = loaded_config
        results["log_lines"] = log_path.read_text(
            encoding="utf-8"
        ).splitlines()
        results["file_sizes"] = {
            str(path.relative_to(base)): path.stat().st_size
            for path in base.rglob("*")
            if path.is_file()
        }

        # Resolve paths before using them. A lexical prefix check alone
        # is insufficient because a path can contain traversal components.
        candidate = (documents / "application.json").resolve()
        resolved_root = base.resolve()

        if not candidate.is_relative_to(resolved_root):
            raise RuntimeError("Resolved path escaped the temporary root.")

        results["resolved_path_inside_root"] = True

        shutil.copy2(config_path, documents / "application.backup.json")
        results["backup_exists"] = (
            documents / "application.backup.json"
        ).is_file()

    results["temporary_data_removed"] = not Path(root).exists()
    return results


def audit_path(path_text: str) -> dict[str, Any]:
    """
    Inspect path metadata without following an application-defined
    trust policy. Existence does not imply that access is authorized.
    """
    path = Path(path_text).expanduser()
    result: dict[str, Any] = {
        "supplied_path": path_text,
        "absolute_path": str(path.absolute()),
        "exists": path.exists(),
        "is_symlink": path.is_symlink(),
    }

    try:
        stat_result = path.stat()
        result.update(
            {
                "is_file": path.is_file(),
                "is_directory": path.is_dir(),
                "size_bytes": stat_result.st_size,
                "modified_utc": datetime.fromtimestamp(
                    stat_result.st_mtime,
                    tz=timezone.utc,
                ).isoformat(),
                "mode_bits": oct(stat_result.st_mode),
            }
        )
    except OSError as exc:
        result["stat_error"] = str(exc)

    if is_windows() and path.exists():
        code, output, error = run_command(
            ["icacls.exe", str(path)],
            timeout=15,
        )
        result["acl_command_succeeded"] = code == 0
        result["acl_output"] = output if code == 0 else error

    return result


def classify_architecture_facts() -> dict[str, str]:
    """Describe architectural boundaries that affect administration."""
    return {
        "user_mode": (
            "Applications normally run in user mode and rely on operating "
            "system services and system calls for privileged operations."
        ),
        "kernel_mode": (
            "The Windows kernel and kernel-mode drivers operate with "
            "privileges unavailable to ordinary user-mode applications."
        ),
        "security_reference_monitor": (
            "Windows access checks use security descriptors, access tokens, "
            "and authorization rules to control access to securable objects."
        ),
        "service_control_manager": (
            "The Service Control Manager coordinates service registration, "
            "configuration, startup, and runtime control."
        ),
        "registry": (
            "The registry stores hierarchical configuration data; hives, "
            "ACLs, value types, and process architecture affect access."
        ),
        "filesystem": (
            "NTFS supports access-control lists, inheritance, alternate "
            "data streams, and hard links; reparse points require care."
        ),
    }


def summarize_audit_findings(
    identity: dict[str, Any],
    filesystem: dict[str, Any],
) -> list[str]:
    findings: list[str] = []

    if identity.get("process_has_administrative_token") is True:
        findings.append(
            "The current process reports administrative-token membership. "
            "Use a standard account for routine tasks."
        )
    elif identity.get("process_has_administrative_token") is False:
        findings.append(
            "The current process does not report administrative-token "
            "membership. Some administrative queries may be restricted."
        )

    for key, item in filesystem.items():
        if isinstance(item, dict) and item.get("exists") is False:
            findings.append(
                f"The expected location '{key}' is absent or unavailable "
                "in this execution environment."
            )

    findings.append(
        "A complete security audit also requires effective access checks, "
        "local and domain policy review, service permissions, update status, "
        "and event-log analysis."
    )
    return findings


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str, ensure_ascii=False))


def run_inspection() -> None:
    heading("Windows architecture")
    print_json(windows_architecture())
    print_json(classify_architecture_facts())

    heading("Current user identity and token")
    identity = collect_identity()
    print_json(identity)

    heading("Filesystem locations")
    filesystem = describe_filesystem_paths()
    print_json(filesystem)

    if is_windows():
        heading("Local users and groups")
        print_json(inspect_local_accounts())

        heading("Read-only registry inspection")
        print_json(inspect_registry_read_only())

        heading("Selected Windows services")
        print_json(inspect_services(limit=20))

    heading("Audit observations")
    for finding in summarize_audit_findings(identity, filesystem):
        print(f"- {finding}")


def run_security_audit() -> None:
    heading("Windows security posture checks")

    if not is_windows():
        print("This audit requires Windows. Architecture facts remain available.")
        print_json(classify_architecture_facts())
        return

    checks = {
        "system_information": ["systeminfo"],
        "effective_identity": ["whoami", "/all"],
        "firewall_profiles": [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "Get-NetFirewallProfile | "
                "Select-Object Name,Enabled,DefaultInboundAction,"
                "DefaultOutboundAction | ConvertTo-Json -Compress"
            ),
        ],
        "pending_reboot_indicators": [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$paths = @("
                "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                "Component Based Servicing\\RebootPending',"
                "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                "WindowsUpdate\\Auto Update\\RebootRequired'"
                "); foreach ($p in $paths) { "
                "[PSCustomObject]@{Path=$p;Exists=(Test-Path $p)} "
                "} | ConvertTo-Json -Compress"
            ),
        ],
    }

    for label, command in checks.items():
        heading(label.replace("_", " ").title())
        code, output, error = run_command(command, timeout=60)
        print_json(
            {
                "command": command,
                "return_code": code,
                "output": output[:12000],
                "error": error[:3000],
            }
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect and demonstrate Windows fundamentals safely."
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Inspect the operating system, identity, registry, and services.",
    )
    parser.add_argument(
        "--filesystem-demo",
        action="store_true",
        help="Run isolated filesystem operations in a temporary directory.",
    )
    parser.add_argument(
        "--security-audit",
        action="store_true",
        help="Run read-only Windows security posture queries.",
    )
    parser.add_argument(
        "--path",
        help="Inspect metadata for a specified path.",
    )
    parser.add_argument(
        "--service",
        help="Inspect a Windows service by its service name.",
    )
    args = parser.parse_args()

    try:
        if args.inspect:
            run_inspection()

        if args.filesystem_demo:
            heading("Isolated filesystem demonstration")
            print_json(filesystem_demo())

        if args.security_audit:
            run_security_audit()

        if args.path:
            heading("Filesystem metadata")
            print_json(audit_path(args.path))

        if args.service:
            heading("Windows service details")
            print_json(inspect_service(args.service))

        if not any(
            [args.inspect, args.filesystem_demo, args.security_audit,
             args.path, args.service]
        ):
            run_inspection()
            heading("Isolated filesystem demonstration")
            print_json(filesystem_demo())

    except (ValueError, RuntimeError, OSError) as exc:
        print(f"Operation failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
