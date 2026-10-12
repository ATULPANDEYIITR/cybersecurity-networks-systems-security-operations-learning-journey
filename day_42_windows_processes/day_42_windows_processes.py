#!/usr/bin/env python3
"""
Windows process, thread, service, and parent-child relationship explorer.

Uses only the Python standard library. Windows-specific details are collected
through PowerShell and CIM when available. The process-tree model and analysis
functions can also run on non-Windows systems using simulated sample data.

Run:
    python windows_processes.py
    python windows_processes.py --live
    python windows_processes.py --tree
    python windows_processes.py --services
    python windows_processes.py --json process_report.json
    python windows_processes.py --sample

Live process and service inspection requires Windows and may be limited by
permissions. The script never terminates processes or changes services.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass
class ProcessInfo:
    pid: int
    name: str
    parent_pid: int | None
    thread_count: int = 0
    executable_path: str | None = None
    command_line: str | None = None
    status: str = "unknown"
    source: str = "sample"
    children: list[int] = field(default_factory=list)


@dataclass
class ServiceInfo:
    name: str
    display_name: str
    state: str
    start_mode: str
    process_id: int | None
    service_type: str = "unknown"
    account: str | None = None


class ProcessInventory:
    """Maintain a validated process snapshot and derive process relationships."""

    def __init__(self, processes: Iterable[ProcessInfo]) -> None:
        self.processes: dict[int, ProcessInfo] = {}
        for process in processes:
            if process.pid <= 0:
                raise ValueError(f"Invalid process ID: {process.pid}")
            if process.pid in self.processes:
                raise ValueError(f"Duplicate process ID: {process.pid}")
            if process.parent_pid is not None and process.parent_pid < 0:
                raise ValueError(f"Invalid parent process ID: {process.parent_pid}")
            self.processes[process.pid] = process
        self._build_relationships()

    def _build_relationships(self) -> None:
        for process in self.processes.values():
            process.children.clear()

        for process in self.processes.values():
            parent = self.processes.get(process.parent_pid)
            if parent is not None:
                parent.children.append(process.pid)

        for process in self.processes.values():
            process.children.sort(key=lambda pid: self.processes[pid].name.lower())

    def roots(self) -> list[ProcessInfo]:
        """Return processes whose parents are absent from this snapshot."""
        return sorted(
            (
                process
                for process in self.processes.values()
                if process.parent_pid not in self.processes
            ),
            key=lambda process: (process.name.lower(), process.pid),
        )

    def descendants(self, pid: int) -> list[ProcessInfo]:
        """Return descendants in breadth-first order."""
        if pid not in self.processes:
            raise KeyError(f"PID {pid} is not present in the snapshot")

        result: list[ProcessInfo] = []
        queue = deque(self.processes[pid].children)
        visited = {pid}

        while queue:
            child_pid = queue.popleft()
            if child_pid in visited:
                continue
            visited.add(child_pid)
            child = self.processes.get(child_pid)
            if child is None:
                continue
            result.append(child)
            queue.extend(child.children)

        return result

    def depth(self, pid: int) -> int:
        """Measure parent-chain depth and detect malformed cyclic relationships."""
        if pid not in self.processes:
            raise KeyError(f"PID {pid} is not present in the snapshot")

        depth = 0
        current = self.processes[pid]
        visited = {pid}

        while current.parent_pid in self.processes:
            parent_pid = current.parent_pid
            if parent_pid in visited:
                raise ValueError(f"Parent cycle detected at PID {parent_pid}")
            visited.add(parent_pid)
            current = self.processes[parent_pid]
            depth += 1

        return depth

    def tree_lines(self) -> list[str]:
        """Render the forest iteratively to avoid recursion-depth failures."""
        lines: list[str] = []
        visited: set[int] = set()

        for root in self.roots():
            stack: list[tuple[int, str, bool]] = [(root.pid, "", False)]
            while stack:
                pid, prefix, is_last = stack.pop()
                if pid in visited:
                    lines.append(f"{prefix}[cycle or repeated PID {pid}]")
                    continue

                visited.add(pid)
                process = self.processes[pid]
                branch = "└── " if is_last else "├── "
                lines.append(
                    f"{prefix}{branch}{process.name} "
                    f"(PID {process.pid}, threads={process.thread_count})"
                )

                child_prefix = prefix + ("    " if is_last else "│   ")
                children = process.children
                for index in range(len(children) - 1, -1, -1):
                    stack.append(
                        (children[index], child_prefix, index == len(children) - 1)
                    )

        # A cycle has no root. Report unvisited entries instead of hiding them.
        for pid in sorted(set(self.processes) - visited):
            lines.append(f"[unreachable or cyclic component begins at PID {pid}]")
            stack = [(pid, "", False)]
            while stack:
                current_pid, prefix, _ = stack.pop()
                if current_pid in visited:
                    continue
                visited.add(current_pid)
                process = self.processes[current_pid]
                lines.append(f"{prefix}{process.name} (PID {current_pid})")
                for child_pid in reversed(process.children):
                    if child_pid not in visited:
                        stack.append((child_pid, prefix + "    ", False))

        return lines

    def summary(self) -> dict[str, Any]:
        total_threads = sum(process.thread_count for process in self.processes.values())
        parent_missing = sum(
            1
            for process in self.processes.values()
            if process.parent_pid is not None
            and process.parent_pid not in self.processes
        )
        return {
            "process_count": len(self.processes),
            "reported_thread_count": total_threads,
            "root_count": len(self.roots()),
            "processes_with_missing_parent": parent_missing,
            "top_processes_by_threads": [
                {
                    "pid": process.pid,
                    "name": process.name,
                    "thread_count": process.thread_count,
                }
                for process in sorted(
                    self.processes.values(),
                    key=lambda item: item.thread_count,
                    reverse=True,
                )[:10]
            ],
        }


def sample_processes() -> list[ProcessInfo]:
    """Provide deterministic example data without requiring Windows."""
    records = [
        (4, "System", None, 180),
        (620, "services.exe", 4, 12),
        (840, "svchost.exe", 620, 28),
        (960, "svchost.exe", 620, 34),
        (1200, "explorer.exe", 620, 42),
        (1300, "notepad.exe", 1200, 8),
        (1450, "powershell.exe", 1200, 14),
        (1500, "python.exe", 1450, 6),
        (1700, "chrome.exe", 1200, 31),
        (1710, "chrome.exe", 1700, 16),
        (1720, "chrome.exe", 1700, 22),
        (1800, "RuntimeBroker.exe", 1200, 10),
    ]
    return [
        ProcessInfo(
            pid=pid,
            name=name,
            parent_pid=parent,
            thread_count=threads,
            status="running",
            source="sample",
        )
        for pid, name, parent, threads in records
    ]


def powershell_executable() -> str | None:
    """Locate a PowerShell executable without assuming its installation path."""
    return shutil.which("powershell.exe") or shutil.which("pwsh")


def run_powershell_json(script: str, timeout: int = 30) -> Any:
    """Execute a read-only PowerShell query and parse its JSON output."""
    executable = powershell_executable()
    if executable is None:
        raise RuntimeError("PowerShell was not found on PATH")

    command = [
        executable,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "RemoteSigned",
        "-Command",
        script,
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"PowerShell query failed with exit code {result.returncode}: "
            f"{result.stderr.strip()}"
        )

    output = result.stdout.strip()
    if not output:
        return []
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"PowerShell returned invalid JSON: {output[:300]!r}"
        ) from exc


def collect_live_processes() -> list[ProcessInfo]:
    """Read process IDs, parent IDs, thread counts, and executable metadata."""
    if platform.system() != "Windows":
        raise OSError("Live Windows process inspection requires Windows")

    script = (
        "$ErrorActionPreference = 'Stop'; "
        "$items = Get-CimInstance Win32_Process | "
        "Select-Object ProcessId, ParentProcessId, Name, ThreadCount, "
        "ExecutablePath, CommandLine; "
        "$items | ConvertTo-Json -Depth 4 -Compress"
    )
    raw = run_powershell_json(script)
    if isinstance(raw, dict):
        raw = [raw]

    processes: list[ProcessInfo] = []
    for item in raw:
        try:
            pid = int(item["ProcessId"])
            parent_value = item.get("ParentProcessId")
            parent_pid = int(parent_value) if parent_value is not None else None
            thread_value = item.get("ThreadCount")
            thread_count = int(thread_value) if thread_value is not None else 0
        except (KeyError, TypeError, ValueError) as exc:
            # Skip malformed records rather than fabricating process identities.
            print(f"Skipping malformed process record: {exc}", file=sys.stderr)
            continue

        processes.append(
            ProcessInfo(
                pid=pid,
                name=str(item.get("Name") or "unknown"),
                parent_pid=parent_pid,
                thread_count=max(thread_count, 0),
                executable_path=item.get("ExecutablePath"),
                command_line=item.get("CommandLine"),
                status="observed",
                source="Win32_Process",
            )
        )
    return processes


def collect_live_services() -> list[ServiceInfo]:
    """Inspect Windows service configuration and current state."""
    if platform.system() != "Windows":
        raise OSError("Live Windows service inspection requires Windows")

    script = (
        "$ErrorActionPreference = 'Stop'; "
        "$items = Get-CimInstance Win32_Service | "
        "Select-Object Name, DisplayName, State, StartMode, ProcessId, "
        "ServiceType, StartName; "
        "$items | ConvertTo-Json -Depth 4 -Compress"
    )
    raw = run_powershell_json(script, timeout=60)
    if isinstance(raw, dict):
        raw = [raw]

    services: list[ServiceInfo] = []
    for item in raw:
        try:
            pid_value = int(item.get("ProcessId") or 0)
        except (TypeError, ValueError):
            pid_value = 0

        services.append(
            ServiceInfo(
                name=str(item.get("Name") or "unknown"),
                display_name=str(item.get("DisplayName") or ""),
                state=str(item.get("State") or "Unknown"),
                start_mode=str(item.get("StartMode") or "Unknown"),
                process_id=pid_value if pid_value > 0 else None,
                service_type=str(item.get("ServiceType") or "unknown"),
                account=item.get("StartName"),
            )
        )
    return services


def correlate_services(
    services: Iterable[ServiceInfo], inventory: ProcessInventory
) -> list[dict[str, Any]]:
    """Associate service records with observed process identities."""
    result: list[dict[str, Any]] = []
    for service in services:
        process = inventory.processes.get(service.process_id or -1)
        result.append(
            {
                **asdict(service),
                "process_found_in_snapshot": process is not None,
                "process_name": process.name if process else None,
            }
        )
    return result


def detect_parent_anomalies(inventory: ProcessInventory) -> list[dict[str, Any]]:
    """
    Report unusual parent relationships without labeling them malicious.

    Parent PIDs can be reused after a process exits. A snapshot may therefore
    contain an old parent PID that now refers to a different process, or no
    parent at all. These records require contextual investigation.
    """
    anomalies: list[dict[str, Any]] = []
    for process in inventory.processes.values():
        if process.parent_pid is None:
            continue
        if process.parent_pid not in inventory.processes:
            anomalies.append(
                {
                    "pid": process.pid,
                    "name": process.name,
                    "parent_pid": process.parent_pid,
                    "reason": "parent_absent_from_snapshot",
                }
            )
    return anomalies


def write_json_report(
    destination: Path,
    inventory: ProcessInventory,
    services: list[ServiceInfo] | None = None,
) -> None:
    """Write a structured report using UTF-8 and atomic replacement."""
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "host_platform": platform.platform(),
        "summary": inventory.summary(),
        "processes": [
            asdict(process)
            for process in sorted(
                inventory.processes.values(), key=lambda item: item.pid
            )
        ],
        "parent_anomalies": detect_parent_anomalies(inventory),
        "services": (
            correlate_services(services, inventory) if services is not None else []
        ),
    }

    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")

    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary, destination)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def print_summary(inventory: ProcessInventory) -> None:
    summary = inventory.summary()
    print("\nProcess inventory")
    print(f"Processes observed: {summary['process_count']}")
    print(f"Reported threads: {summary['reported_thread_count']}")
    print(f"Roots in snapshot: {summary['root_count']}")
    print(f"Missing parent records: {summary['processes_with_missing_parent']}")
    print("\nProcesses with the highest reported thread counts:")
    for item in summary["top_processes_by_threads"]:
        print(
            f"  PID {item['pid']:>6}  "
            f"{item['thread_count']:>4} threads  {item['name']}"
        )


def print_services(services: Iterable[ServiceInfo]) -> None:
    print("\nWindows services")
    for service in sorted(services, key=lambda item: item.name.lower()):
        pid_text = str(service.process_id) if service.process_id is not None else "-"
        print(
            f"{service.name} | {service.state} | "
            f"startup={service.start_mode} | PID={pid_text}"
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect Windows process trees, threads, and services."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="collect live Windows process data",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="use deterministic sample data",
    )
    parser.add_argument("--tree", action="store_true", help="print the process tree")
    parser.add_argument(
        "--services", action="store_true", help="inspect Windows services"
    )
    parser.add_argument("--json", type=Path, help="write a JSON report to this path")
    parser.add_argument(
        "--pid",
        type=int,
        help="show descendants of the selected process ID",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    try:
        if args.live and args.sample:
            raise ValueError("Choose either --live or --sample, not both")

        if args.live:
            processes = collect_live_processes()
        elif args.sample or platform.system() != "Windows":
            processes = sample_processes()
            if not args.sample:
                print(
                    "Non-Windows host detected; using sample process data. "
                    "Pass --sample to make this choice explicit."
                )
        else:
            processes = collect_live_processes()

        inventory = ProcessInventory(processes)
        print_summary(inventory)

        if args.tree:
            print("\nParent-child process tree")
            for line in inventory.tree_lines():
                print(line)

        if args.pid is not None:
            descendants = inventory.descendants(args.pid)
            print(f"\nDescendants of PID {args.pid}")
            if not descendants:
                print("No descendants found in this snapshot.")
            for process in descendants:
                print(
                    f"PID={process.pid} parent={process.parent_pid} "
                    f"threads={process.thread_count} name={process.name}"
                )

        services: list[ServiceInfo] | None = None
        if args.services:
            services = collect_live_services()
            print_services(services)

        if args.json:
            write_json_report(args.json, inventory, services)
            print(f"\nReport written to {args.json.expanduser().resolve()}")

        return 0

    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
