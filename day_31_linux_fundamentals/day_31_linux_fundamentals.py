#!/usr/bin/env python3
"""
Linux Fundamentals: Filesystem, Processes, Users, Groups, Permissions,
Packages, and Services

A self-contained educational simulator and inspection utility.

The program deliberately uses only the Python standard library. It can:
- Inspect Linux filesystem concepts safely.
- Parse and explain Unix permission bits.
- Model users, groups, ownership, and access decisions.
- Inspect processes from /proc when running on Linux.
- Inspect package/service concepts without modifying the host.
- Simulate package installation and service lifecycle operations.
- Demonstrate realistic Linux administration workflows.

The script does not require root privileges and does not execute destructive
system-administration commands.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Filesystem fundamentals
# ---------------------------------------------------------------------------

@dataclass
class FileMetadata:
    path: str
    file_type: str
    mode: str
    owner_uid: int
    group_gid: int
    size: int
    readable: bool
    writable: bool
    executable: bool


def classify_file_mode(mode: int) -> str:
    """Translate the file-type portion of a Unix mode into a human label."""
    if stat.S_ISREG(mode):
        return "regular file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symbolic link"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    if stat.S_ISFIFO(mode):
        return "FIFO"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "unknown"


def permission_string(mode: int) -> str:
    """Return the familiar ten-character ls-style permission representation."""
    result = stat.filemode(mode)

    # stat.filemode already accounts for special bits such as setuid,
    # setgid, and the sticky bit.
    return result


def octal_permissions(mode: int) -> str:
    """Return the traditional four-digit Unix permission representation."""
    return f"{stat.S_IMODE(mode):04o}"


def inspect_path(path: Path) -> FileMetadata:
    """
    Inspect a path using lstat so a symbolic link itself can be examined
    without silently following it.
    """
    metadata = path.lstat()
    return FileMetadata(
        path=str(path),
        file_type=classify_file_mode(metadata.st_mode),
        mode=permission_string(metadata.st_mode),
        owner_uid=metadata.st_uid,
        group_gid=metadata.st_gid,
        size=metadata.st_size,
        readable=os.access(path, os.R_OK),
        writable=os.access(path, os.W_OK),
        executable=os.access(path, os.X_OK),
    )


def filesystem_demo() -> None:
    print("\n=== Linux Filesystem ===")

    important_paths = [
        "/",
        "/etc",
        "/home",
        "/tmp",
        "/var",
        "/usr",
        "/proc",
        "/sys",
        "/dev",
    ]

    print("Linux uses a single directory tree rooted at '/'.")
    print("Common top-level roles:")

    roles = {
        "/": "filesystem root",
        "/etc": "system and application configuration",
        "/home": "regular users' home directories",
        "/tmp": "temporary files",
        "/var": "variable data such as logs, caches, and queues",
        "/usr": "most user-space programs and supporting files",
        "/proc": "kernel-provided process and system information",
        "/sys": "kernel device and subsystem information",
        "/dev": "device nodes exposed to user space",
    }

    for path, purpose in roles.items():
        exists = Path(path).exists()
        print(f"  {path:<6} {'present' if exists else 'not present':<12} {purpose}")

    current = Path.cwd()
    try:
        metadata = inspect_path(current)
        print("\nCurrent working directory:")
        print(f"  path       : {metadata.path}")
        print(f"  type       : {metadata.file_type}")
        print(f"  permissions: {metadata.mode}")
        print(f"  octal      : {octal_permissions(current.stat().st_mode)}")
        print(f"  uid/gid    : {metadata.owner_uid}/{metadata.group_gid}")
    except OSError as exc:
        print(f"Unable to inspect {current}: {exc}")


# ---------------------------------------------------------------------------
# Permissions, users, and groups
# ---------------------------------------------------------------------------

@dataclass
class LinuxUser:
    username: str
    uid: int
    primary_group: str
    supplementary_groups: set[str] = field(default_factory=set)

    @property
    def groups(self) -> set[str]:
        return {self.primary_group, *self.supplementary_groups}


@dataclass
class LinuxFile:
    name: str
    owner: str
    group: str
    mode: int
    is_directory: bool = False


def parse_symbolic_permissions(value: str) -> int:
    """
    Convert rwxrwxrwx-style permissions into a Unix mode.

    Special forms such as s/S/t/T are supported because they matter in real
    Linux permissions, especially for setuid, setgid, and shared directories.
    """
    if len(value) != 9:
        raise ValueError("Permission text must contain exactly nine characters")

    mode = 0
    triplets = [(0, 6), (3, 3), (6, 0)]

    for start, shift in triplets:
        chars = value[start:start + 3]

        if chars[0] == "r":
            mode |= 4 << shift
        elif chars[0] != "-":
            raise ValueError(f"Invalid read permission: {chars[0]}")

        if chars[1] == "w":
            mode |= 2 << shift
        elif chars[1] != "-":
            raise ValueError(f"Invalid write permission: {chars[1]}")

        execute = chars[2]
        if execute in {"x", "s", "t"}:
            mode |= 1 << shift
        elif execute not in {"-", "S", "T"}:
            raise ValueError(f"Invalid execute permission: {execute}")

    # Handle special bits explicitly. setuid/setgid/sticky are represented
    # by the execute character in the owner/group/other triplets.
    if value[2] in {"s", "S"}:
        mode |= stat.S_ISUID
    if value[5] in {"s", "S"}:
        mode |= stat.S_ISGID
    if value[8] in {"t", "T"}:
        mode |= stat.S_ISVTX

    return mode


def explain_mode(mode: int) -> str:
    """Explain the permission groups without treating them as independent users."""
    return (
        f"{permission_string(mode)} "
        f"(octal {stat.S_IMODE(mode):04o})"
    )


def effective_permission(
    user: LinuxUser,
    file: LinuxFile,
    requested: str,
) -> bool:
    """
    Model the kernel's owner/group/other permission selection.

    The important rule is that Linux does not combine owner permissions with
    group permissions. If the process owner matches the inode owner, the
    owner class is selected. Otherwise, if the process has the file's group,
    the group class is selected. Otherwise, the other class is selected.
    """
    if requested not in {"r", "w", "x"}:
        raise ValueError("requested permission must be r, w, or x")

    if user.username == file.owner:
        shift = 6
    elif file.group in user.groups:
        shift = 3
    else:
        shift = 0

    bit = {"r": 4, "w": 2, "x": 1}[requested]
    return bool(stat.S_IMODE(file.mode) & (bit << shift))


def permission_demo() -> None:
    print("\n=== Users, Groups, and Permissions ===")

    alice = LinuxUser(
        username="alice",
        uid=1001,
        primary_group="engineering",
        supplementary_groups={"developers"},
    )

    bob = LinuxUser(
        username="bob",
        uid=1002,
        primary_group="finance",
        supplementary_groups={"auditors"},
    )

    deployment_script = LinuxFile(
        name="deploy.sh",
        owner="alice",
        group="developers",
        mode=0o750,
    )

    print(
        f"{deployment_script.name}: "
        f"owner={deployment_script.owner}, "
        f"group={deployment_script.group}, "
        f"permissions={explain_mode(deployment_script.mode)}"
    )

    for user in (alice, bob):
        decisions = {
            permission: effective_permission(
                user, deployment_script, permission
            )
            for permission in ("r", "w", "x")
        }
        print(f"{user.username:<5} groups={sorted(user.groups)}")
        print(f"       access={decisions}")

    print("\nPermission semantics:")
    print("  r on a regular file permits reading file contents.")
    print("  w permits modifying file contents, subject to ownership and policy.")
    print("  x permits execution for a regular file.")
    print("  x on a directory permits traversal; r permits listing entries.")
    print("  w on a directory permits changing directory entries when traversal is available.")

    shared_directory = LinuxFile(
        name="/srv/project",
        owner="alice",
        group="developers",
        mode=0o2775,
        is_directory=True,
    )
    print(
        f"\nShared directory example: {shared_directory.name} "
        f"{explain_mode(shared_directory.mode)}"
    )
    print("The leading 2 represents setgid, which can cause new files to inherit")
    print("the directory's group, a useful property for collaborative project trees.")


# ---------------------------------------------------------------------------
# Real Linux user/group inspection
# ---------------------------------------------------------------------------

def current_identity_demo() -> None:
    print("\n=== Current Process Identity ===")

    uid = os.getuid() if hasattr(os, "getuid") else None
    gid = os.getgid() if hasattr(os, "getgid") else None

    print(f"Operating system: {platform.system()}")
    print(f"Username       : {os.environ.get('USER') or os.environ.get('USERNAME', 'unknown')}")

    if uid is not None:
        print(f"UID            : {uid}")
        print(f"GID            : {gid}")

    try:
        import pwd

        if uid is not None:
            account = pwd.getpwuid(uid)
            print(f"Home directory : {account.pw_dir}")
            print(f"Login shell    : {account.pw_shell}")
    except (ImportError, KeyError):
        print("POSIX account database is unavailable on this platform.")

    try:
        import grp

        if gid is not None:
            group = grp.getgrgid(gid)
            print(f"Primary group  : {group.gr_name}")
    except (ImportError, KeyError):
        print("POSIX group database is unavailable on this platform.")


# ---------------------------------------------------------------------------
# Process fundamentals
# ---------------------------------------------------------------------------

@dataclass
class ProcessSnapshot:
    pid: int
    command: str
    state: str
    parent_pid: int | None
    user: str


def read_proc_status(pid: int) -> dict[str, str]:
    """
    Parse /proc/<pid>/status.

    /proc is a kernel-generated pseudo-filesystem, so these values represent
    current process state rather than ordinary static files on disk.
    """
    result: dict[str, str] = {}
    status_path = Path("/proc") / str(pid) / "status"

    with status_path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()

    return result


def inspect_process(pid: int) -> ProcessSnapshot:
    status = read_proc_status(pid)

    state = status.get("State", "unknown")
    command = status.get("Name", "unknown")

    state_code = state.split()[0] if state else "?"
    parent_text = status.get("PPid", "")
    parent_pid = int(parent_text) if parent_text.isdigit() else None

    uid_text = status.get("Uid", "")
    uid = int(uid_text.split()[0]) if uid_text else None

    username = str(uid)
    try:
        import pwd

        if uid is not None:
            username = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        pass

    return ProcessSnapshot(
        pid=pid,
        command=command,
        state=state_code,
        parent_pid=parent_pid,
        user=username,
    )


def list_processes(limit: int = 15) -> list[ProcessSnapshot]:
    """Read a bounded process snapshot from Linux's /proc filesystem."""
    proc = Path("/proc")
    if not proc.is_dir():
        return []

    processes: list[ProcessSnapshot] = []

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue

        try:
            processes.append(inspect_process(int(entry.name)))
        except (OSError, ValueError):
            # Processes can disappear between directory enumeration and read.
            # This is normal because process lifetimes are concurrent with
            # inspection.
            continue

    processes.sort(key=lambda item: item.pid)
    return processes[:limit]


def process_demo() -> None:
    print("\n=== Processes ===")

    if platform.system() != "Linux":
        print("The /proc process demonstration requires Linux.")
        return

    processes = list_processes()

    if not processes:
        print("No readable processes were found.")
        return

    print(f"{'PID':>7} {'PPID':>7} {'STATE':<6} {'USER':<16} COMMAND")
    for process in processes:
        print(
            f"{process.pid:>7} "
            f"{str(process.parent_pid):>7} "
            f"{process.state:<6} "
            f"{process.user:<16} "
            f"{process.command}"
        )

    print("\nProcess relationships are represented by parent PIDs.")
    print("A process is a running program instance with its own address space,")
    print("file-descriptor table, credentials, scheduling state, and resources.")


def safe_subprocess_demo() -> None:
    """
    Demonstrate process creation without shell interpolation.

    Passing an argument list instead of shell=True avoids shell parsing and
    reduces command-injection risk when values originate from external input.
    """
    print("\n=== Safe Process Creation ===")

    command = [
        sys.executable,
        "-c",
        "print('child process: executed without a shell')",
    ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    print(completed.stdout.strip())


# ---------------------------------------------------------------------------
# Package management model
# ---------------------------------------------------------------------------

@dataclass
class Package:
    name: str
    version: str
    dependencies: tuple[str, ...] = ()
    files: tuple[str, ...] = ()


class PackageManagerSimulator:
    """
    Small dependency-aware package manager model.

    Real Linux distributions use dedicated package managers such as apt/dpkg,
    dnf/rpm, pacman, zypper, or apk. This class demonstrates dependency
    resolution without changing the host operating system.
    """

    def __init__(self, repository: Iterable[Package]) -> None:
        self.repository = {package.name: package for package in repository}
        self.installed: dict[str, Package] = {}

    def resolve(self, name: str) -> list[Package]:
        resolved: list[Package] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(package_name: str) -> None:
            if package_name in visited:
                return

            if package_name in visiting:
                raise RuntimeError(
                    f"dependency cycle detected at {package_name}"
                )

            if package_name not in self.repository:
                raise KeyError(f"package not found: {package_name}")

            visiting.add(package_name)
            package = self.repository[package_name]

            for dependency in package.dependencies:
                if dependency not in self.installed:
                    visit(dependency)

            visiting.remove(package_name)
            visited.add(package_name)
            resolved.append(package)

        visit(name)
        return resolved

    def install(self, name: str) -> list[str]:
        plan = self.resolve(name)
        installed_now: list[str] = []

        for package in plan:
            if package.name in self.installed:
                continue
            self.installed[package.name] = package
            installed_now.append(package.name)

        return installed_now


def package_demo() -> None:
    print("\n=== Packages ===")

    repository = [
        Package("libssl", "3.0", files=("/usr/lib/libssl.so",)),
        Package("curl", "8.0", dependencies=("libssl",), files=("/usr/bin/curl",)),
        Package("web-monitor", "2.4", dependencies=("curl",), files=("/usr/bin/web-monitor",)),
    ]

    manager = PackageManagerSimulator(repository)
    plan = manager.resolve("web-monitor")

    print("Dependency resolution plan:")
    for package in plan:
        dependency_text = ", ".join(package.dependencies) or "none"
        print(
            f"  {package.name}-{package.version} "
            f"depends on {dependency_text}"
        )

    installed = manager.install("web-monitor")
    print(f"Installed in simulator: {installed}")

    print("\nA real package manager also maintains package metadata, verifies")
    print("package archives and signatures according to distribution policy,")
    print("tracks ownership of installed files, and handles upgrades/removals.")


# ---------------------------------------------------------------------------
# Service management model
# ---------------------------------------------------------------------------

class ServiceState:
    STOPPED = "stopped"
    RUNNING = "running"
    FAILED = "failed"


@dataclass
class ServiceUnit:
    name: str
    command: tuple[str, ...]
    state: str = ServiceState.STOPPED
    restart_on_failure: bool = False


class ServiceManagerSimulator:
    """
    Model the lifecycle of a service.

    Modern Linux systems commonly use systemd. A real systemd unit has much
    richer semantics, including dependencies, targets, supervision, logging,
    resource controls, sandboxing, and restart policies.
    """

    def __init__(self) -> None:
        self.services: dict[str, ServiceUnit] = {}

    def register(self, service: ServiceUnit) -> None:
        if service.name in self.services:
            raise ValueError(f"service already exists: {service.name}")
        self.services[service.name] = service

    def start(self, name: str) -> None:
        service = self.services[name]
        if service.state == ServiceState.RUNNING:
            return
        service.state = ServiceState.RUNNING

    def stop(self, name: str) -> None:
        service = self.services[name]
        service.state = ServiceState.STOPPED

    def fail(self, name: str) -> None:
        service = self.services[name]
        service.state = ServiceState.FAILED

        if service.restart_on_failure:
            self.start(name)

    def status(self, name: str) -> ServiceUnit:
        return self.services[name]


def service_demo() -> None:
    print("\n=== Services ===")

    manager = ServiceManagerSimulator()

    manager.register(
        ServiceUnit(
            name="web-monitor.service",
            command=("/usr/local/bin/web-monitor", "--serve"),
            restart_on_failure=True,
        )
    )

    service = manager.status("web-monitor.service")
    print(f"Initial state: {service.state}")

    manager.start(service.name)
    print(f"After start : {manager.status(service.name).state}")

    manager.fail(service.name)
    print(
        "After simulated failure with restart policy: "
        f"{manager.status(service.name).state}"
    )

    manager.stop(service.name)
    print(f"After stop  : {manager.status(service.name).state}")

    print("\nTypical service lifecycle:")
    print("configuration -> dependency evaluation -> process start -> supervision")
    print("-> logging/status reporting -> stop/restart/failure handling")


# ---------------------------------------------------------------------------
# Permission validation and security cases
# ---------------------------------------------------------------------------

def permission_security_demo() -> None:
    print("\n=== Permission and Security Cases ===")

    cases = {
        "private file": "rw-------",
        "team script": "rwxr-x---",
        "public executable": "rwxr-xr-x",
        "shared directory": "rwxrwsr-x",
        "temporary shared directory": "rwxrwxrwt",
    }

    for label, symbolic in cases.items():
        mode = parse_symbolic_permissions(symbolic)
        print(
            f"{label:<26} {symbolic} -> "
            f"{oct(stat.S_IMODE(mode))} -> {explain_mode(mode)}"
        )

    print("\nImportant distinctions:")
    print("  chmod changes permission bits; it does not change ownership.")
    print("  chown changes ownership and normally requires elevated privileges.")
    print("  chgrp changes the group associated with an inode.")
    print("  umask removes permission bits requested during creation.")
    print("  ACLs can provide access rules more granular than the traditional")
    print("  owner/group/other permission classes.")

    print("\nSecurity concerns:")
    print("  Avoid world-writable files and directories unless their design requires them.")
    print("  Avoid running long-lived services as root when a dedicated service account suffices.")
    print("  Protect private keys and credentials with restrictive ownership and modes.")
    print("  Treat writable PATH directories and writable service configuration as privilege risks.")
    print("  Do not assume file permissions alone provide application-level authorization.")


# ---------------------------------------------------------------------------
# Umask demonstration
# ---------------------------------------------------------------------------

def apply_umask(requested_mode: int, umask: int) -> int:
    """
    Linux creation APIs conceptually apply umask by removing requested bits.

    The kernel performs the actual operation; this function isolates the rule
    so it can be demonstrated without creating files.
    """
    return requested_mode & ~umask


def umask_demo() -> None:
    print("\n=== Umask ===")

    requested_file_mode = 0o666
    requested_directory_mode = 0o777
    common_umask = 0o027

    file_result = apply_umask(requested_file_mode, common_umask)
    directory_result = apply_umask(requested_directory_mode, common_umask)

    print(f"Requested file mode      : {oct(requested_file_mode)}")
    print(f"Umask                    : {oct(common_umask)}")
    print(f"Effective creation mode  : {oct(file_result)}")
    print()
    print(f"Requested directory mode : {oct(requested_directory_mode)}")
    print(f"Effective creation mode  : {oct(directory_result)}")

    print(
        "\nThe umask is not a permission grant. It is a mask that removes "
        "permission bits from requested creation modes."
    )


# ---------------------------------------------------------------------------
# Integrated repository deployment scenario
# ---------------------------------------------------------------------------

@dataclass
class DeploymentArtifact:
    path: str
    owner: str
    group: str
    mode: int


class LinuxDeploymentModel:
    """
    Combine users/groups, filesystem ownership, package dependencies, and
    service lifecycle into one deployment scenario.
    """

    def __init__(self) -> None:
        self.artifacts: list[DeploymentArtifact] = []

    def add_artifact(self, artifact: DeploymentArtifact) -> None:
        if not artifact.path.startswith("/srv/"):
            raise ValueError(
                "deployment artifacts in this model must live under /srv/"
            )
        self.artifacts.append(artifact)

    def validate(self) -> list[str]:
        errors: list[str] = []

        for artifact in self.artifacts:
            if artifact.mode & stat.S_IWOTH:
                errors.append(
                    f"{artifact.path}: world-writable deployment artifact"
                )

            if artifact.owner == "root" and artifact.mode & stat.S_IWOTH:
                errors.append(
                    f"{artifact.path}: root-owned artifact is world-writable"
                )

            if artifact.path.endswith(".sh") and not artifact.mode & stat.S_IXUSR:
                errors.append(
                    f"{artifact.path}: deployment script is not owner-executable"
                )

        return errors


def integrated_scenario_demo() -> None:
    print("\n=== Integrated Linux Deployment Scenario ===")

    deployment = LinuxDeploymentModel()

    deployment.add_artifact(
        DeploymentArtifact(
            path="/srv/web-monitor/web-monitor.service",
            owner="root",
            group="root",
            mode=0o644,
        )
    )

    deployment.add_artifact(
        DeploymentArtifact(
            path="/srv/web-monitor/bin/web-monitor.sh",
            owner="deploy",
            group="webops",
            mode=0o750,
        )
    )

    deployment.add_artifact(
        DeploymentArtifact(
            path="/srv/web-monitor/config",
            owner="root",
            group="webops",
            mode=0o640,
        )
    )

    errors = deployment.validate()

    print("Deployment artifacts:")
    for artifact in deployment.artifacts:
        print(
            f"  {artifact.path:<45} "
            f"{artifact.owner}:{artifact.group} "
            f"{oct(artifact.mode)}"
        )

    if errors:
        print("\nValidation errors:")
        for error in errors:
            print(f"  {error}")
    else:
        print("\nPermission validation passed.")

    print("\nOperational relationship:")
    print("  A package can place files on the filesystem.")
    print("  Ownership and permissions determine which accounts can access them.")
    print("  A service manager can start a program using those files.")
    print("  The running process receives credentials that affect its resource access.")
    print("  Logs and process state provide operational evidence when failures occur.")


# ---------------------------------------------------------------------------
# Real command inspection
# ---------------------------------------------------------------------------

def command_available(command: str) -> bool:
    from shutil import which

    return which(command) is not None


def inspect_linux_commands() -> None:
    print("\n=== Available Linux Administration Interfaces ===")

    commands = [
        "ls",
        "stat",
        "ps",
        "id",
        "chmod",
        "chown",
        "find",
        "systemctl",
        "journalctl",
        "apt",
        "dnf",
        "rpm",
        "pacman",
    ]

    for command in commands:
        print(f"  {command:<12} {'available' if command_available(command) else 'not found'}")

    print("\nAvailability depends on distribution and installed packages.")
    print("The presence of a command does not imply that the current user")
    print("has permission to perform every operation exposed by it.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_all_demos() -> None:
    filesystem_demo()
    current_identity_demo()
    permission_demo()
    permission_security_demo()
    umask_demo()
    process_demo()
    safe_subprocess_demo()
    package_demo()
    service_demo()
    integrated_scenario_demo()
    inspect_linux_commands()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Linux fundamentals educational simulator and inspection utility."
        )
    )
    parser.add_argument(
        "--path",
        type=Path,
        help="Inspect one filesystem path instead of only running the demonstrations.",
    )
    parser.add_argument(
        "--pid",
        type=int,
        help="Inspect one Linux process through /proc.",
    )
    return parser.parse_args()


def inspect_requested_path(path: Path) -> None:
    print(f"\n=== Path Inspection: {path} ===")
    try:
        metadata = inspect_path(path)
        print(f"type        : {metadata.file_type}")
        print(f"permissions : {metadata.mode}")
        print(f"octal       : {octal_permissions(path.stat().st_mode)}")
        print(f"owner UID   : {metadata.owner_uid}")
        print(f"group GID   : {metadata.group_gid}")
        print(f"size        : {metadata.size} bytes")
        print(f"readable    : {metadata.readable}")
        print(f"writable    : {metadata.writable}")
        print(f"executable  : {metadata.executable}")
    except FileNotFoundError:
        print("Path does not exist.")
    except PermissionError:
        print("Permission denied while inspecting the path.")
    except OSError as exc:
        print(f"Filesystem error: {exc}")


def inspect_requested_process(pid: int) -> None:
    print(f"\n=== Process Inspection: PID {pid} ===")

    if platform.system() != "Linux":
        print("Process inspection through /proc requires Linux.")
        return

    try:
        process = inspect_process(pid)
    except FileNotFoundError:
        print("The process does not exist or exited before inspection.")
        return
    except PermissionError:
        print("Permission denied while reading process information.")
        return
    except OSError as exc:
        print(f"Process inspection failed: {exc}")
        return

    print(f"PID        : {process.pid}")
    print(f"PPID       : {process.parent_pid}")
    print(f"command    : {process.command}")
    print(f"state      : {process.state}")
    print(f"user       : {process.user}")


def main() -> int:
    args = parse_arguments()

    print("Linux Fundamentals Laboratory")
    print("==============================")
    print(
        "This program models core Linux administration concepts without "
        "performing privileged or destructive changes."
    )

    if args.path:
        inspect_requested_path(args.path)

    if args.pid is not None:
        inspect_requested_process(args.pid)

    if not args.path and args.pid is None:
        run_all_demos()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
