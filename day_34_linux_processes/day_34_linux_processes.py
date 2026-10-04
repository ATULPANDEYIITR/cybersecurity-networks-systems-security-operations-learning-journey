#!/usr/bin/env python3
"""
Linux Processes: processes, PIDs, signals, background processes, and process trees.

This script is both an executable laboratory and a practical reference. It uses
Linux/POSIX process facilities through Python's standard library.

Run on Linux:

    python3 linux_processes.py

The script demonstrates:
- Process creation and PID relationships
- Parent and child processes
- Process exit status and waiting
- Background processes
- Signals and signal handlers
- Graceful versus forced termination
- Process groups and signal delivery
- Process trees
- Zombie-process behavior
- Timeouts and failure handling
- Safe subprocess management
- Inspection of real Linux processes through /proc
- A small process-supervision example
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


IS_LINUX = sys.platform.startswith("linux")


def require_linux() -> None:
    if not IS_LINUX:
        raise SystemExit(
            "This laboratory requires Linux because it uses Linux/POSIX process "
            "features such as /proc, fork(), process groups, and Unix signals."
        )


def heading(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def show_current_process() -> None:
    """Display the identity and hierarchy information of the running process."""
    heading("Current Process Identity")

    print(f"Process ID (PID):             {os.getpid()}")
    print(f"Parent Process ID (PPID):    {os.getppid()}")
    print(f"Process Group ID (PGID):      {os.getpgid(0)}")
    print(f"Session ID (SID):             {os.getsid(0)}")
    print(f"Executable:                   {sys.executable}")
    print(f"Current working directory:    {Path.cwd()}")


def demonstrate_fork() -> None:
    """
    fork() duplicates the current process.

    After fork(), both processes continue from the same point, but fork()
    returns different values:
      parent: child's PID
      child: 0

    The child exits independently. The parent calls waitpid() so that the
    child is reaped and does not remain a zombie.
    """
    heading("Process Creation with fork()")

    child_pid = os.fork()

    if child_pid == 0:
        print(
            f"[child] PID={os.getpid()}, PPID={os.getppid()} "
            f"created by parent PID={os.getppid()}"
        )
        time.sleep(0.5)
        print(f"[child] PID={os.getpid()} exiting with status 7")
        os._exit(7)

    print(f"[parent] PID={os.getpid()} created child PID={child_pid}")

    waited_pid, status = os.waitpid(child_pid, 0)
    exit_code = os.waitstatus_to_exitcode(status)

    print(f"[parent] waitpid() returned PID={waited_pid}")
    print(f"[parent] Child exit code={exit_code}")

    if os.WIFEXITED(status):
        print("[parent] Child terminated normally.")
    elif os.WIFSIGNALED(status):
        print(f"[parent] Child was terminated by signal {os.WTERMSIG(status)}.")


SIGNAL_CHILD_CODE = r"""
import os
import signal
import sys
import time

received = []

def handle_signal(signum, frame):
    received.append(signum)
    print(
        f"[signal-child] PID={os.getpid()} received "
        f"{signal.Signals(signum).name}",
        flush=True,
    )
    if signum == signal.SIGTERM:
        print("[signal-child] Performing graceful shutdown.", flush=True)
        sys.exit(0)

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

print(f"[signal-child] ready PID={os.getpid()}", flush=True)

while True:
    time.sleep(0.25)
"""


def demonstrate_signals() -> None:
    """
    Signals are asynchronous notifications delivered to processes.

    SIGTERM is normally preferable to SIGKILL because a process can catch
    SIGTERM and close files, release resources, finish transactions, and
    terminate cleanly. SIGKILL cannot be caught or handled by the target.
    """
    heading("Signals and Graceful Termination")

    child = subprocess.Popen(
        [sys.executable, "-c", SIGNAL_CHILD_CODE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    assert child.stdout is not None

    ready_line = child.stdout.readline().strip()
    print(f"Supervisor observed: {ready_line}")

    print(f"Sending SIGTERM to PID {child.pid}")
    child.send_signal(signal.SIGTERM)

    try:
        return_code = child.wait(timeout=3)
        print(f"Child terminated gracefully with exit code {return_code}")
    except subprocess.TimeoutExpired:
        print("Child ignored SIGTERM or failed to terminate in time.")
        child.kill()
        child.wait()
        print("SIGKILL was required as a final fallback.")


def demonstrate_background_process() -> None:
    """
    Popen() returns immediately, leaving the child process running while the
    parent continues. This is the Python equivalent of launching a background
    process rather than blocking on it immediately.
    """
    heading("Background Process")

    background_code = r"""
import os
import time

print(f"background PID={os.getpid()}", flush=True)

for second in range(1, 4):
    print(f"background PID={os.getpid()} tick={second}", flush=True)
    time.sleep(1)

print("background process completed", flush=True)
"""

    process = subprocess.Popen(
        [sys.executable, "-c", background_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    print(f"Parent started background PID={process.pid}")
    print("Parent continues immediately without waiting for completion.")

    stdout, stderr = process.communicate(timeout=5)

    print("Captured background output:")
    print(stdout.rstrip())

    if stderr:
        print("Background stderr:")
        print(stderr.rstrip())

    print(f"Background exit code: {process.returncode}")


def demonstrate_process_tree() -> None:
    """
    A process tree describes parent-child relationships. Linux exposes
    hierarchy information through /proc/<pid>/status and related interfaces.
    """
    heading("Process Tree")

    parent_code = r"""
import os
import subprocess
import sys
import time

print(f"tree-parent PID={os.getpid()}", flush=True)

child_code = r'''
import os
import time
print(f"tree-child PID={os.getpid()} PPID={os.getppid()}", flush=True)
time.sleep(1.5)
'''

child = subprocess.Popen(
    [sys.executable, "-c", child_code],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

print(f"tree-parent created child PID={child.pid}", flush=True)
time.sleep(1)
child.wait()
print("tree-parent finished", flush=True)
"""

    process = subprocess.Popen(
        [sys.executable, "-c", parent_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout, stderr = process.communicate(timeout=5)

    print(stdout.rstrip())
    if stderr:
        print(stderr.rstrip())

    print(f"Tree demonstration exit code: {process.returncode}")


def parse_proc_status(pid: int) -> dict[str, str]:
    """Read selected fields from Linux's /proc/<pid>/status file."""
    path = Path("/proc") / str(pid) / "status"

    result: dict[str, str] = {}

    try:
        for line in path.read_text(errors="replace").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            result[key] = value.strip()
    except (FileNotFoundError, PermissionError):
        return {}

    return result


def inspect_process(pid: int) -> Optional[dict[str, str]]:
    """Return useful metadata for a live Linux process."""
    status = parse_proc_status(pid)

    if not status:
        return None

    return {
        "Name": status.get("Name", ""),
        "State": status.get("State", ""),
        "Pid": status.get("Pid", ""),
        "PPid": status.get("PPid", ""),
        "Threads": status.get("Threads", ""),
        "VmRSS": status.get("VmRSS", ""),
        "Uid": status.get("Uid", ""),
    }


def demonstrate_proc_filesystem() -> None:
    """
    /proc is a pseudo-filesystem exposing kernel-maintained process metadata.
    It is not ordinary persistent storage: entries can disappear as processes
    terminate.
    """
    heading("Inspecting a Process through /proc")

    current = inspect_process(os.getpid())

    if current is None:
        print("Could not inspect the current process.")
        return

    for key, value in current.items():
        print(f"{key:12}: {value}")

    print(f"/proc/{os.getpid()}/cmdline:")
    try:
        cmdline = Path(f"/proc/{os.getpid()}/cmdline").read_bytes()
        print(cmdline.replace(b"\x00", b" ").decode(errors="replace").strip())
    except (FileNotFoundError, PermissionError) as exc:
        print(f"Unavailable: {exc}")


@dataclass
class ProcessRecord:
    """Minimal information needed to represent a process-tree node."""

    pid: int
    ppid: int
    name: str
    state: str


def read_process_records() -> list[ProcessRecord]:
    """
    Build a process inventory from /proc.

    Directory traversal can race with process creation and termination, so
    disappearing entries are treated as normal rather than fatal errors.
    """
    records: list[ProcessRecord] = []

    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)
        status = parse_proc_status(pid)

        if not status:
            continue

        try:
            ppid = int(status.get("PPid", "0"))
        except ValueError:
            ppid = 0

        records.append(
            ProcessRecord(
                pid=pid,
                ppid=ppid,
                name=status.get("Name", "?"),
                state=status.get("State", "?"),
            )
        )

    return records


def build_process_tree(records: list[ProcessRecord]) -> dict[int, list[ProcessRecord]]:
    """Index process records by parent PID."""
    children: dict[int, list[ProcessRecord]] = {}

    for record in records:
        children.setdefault(record.ppid, []).append(record)

    for siblings in children.values():
        siblings.sort(key=lambda item: item.pid)

    return children


def print_process_tree(
    children: dict[int, list[ProcessRecord]],
    parent_pid: int,
    prefix: str = "",
    depth: int = 0,
    max_depth: int = 3,
) -> None:
    """Print a bounded process hierarchy to avoid enormous output."""
    if depth >= max_depth:
        return

    for index, record in enumerate(children.get(parent_pid, [])):
        branch = "└── " if index == len(children[parent_pid]) - 1 else "├── "
        print(
            f"{prefix}{branch}{record.pid} {record.name} "
            f"[{record.state}]"
        )

        next_prefix = prefix + ("    " if index == len(children[parent_pid]) - 1 else "│   ")
        print_process_tree(
            children,
            record.pid,
            next_prefix,
            depth + 1,
            max_depth,
        )


def demonstrate_real_process_tree() -> None:
    heading("Real Linux Process Tree")

    records = read_process_records()
    children = build_process_tree(records)

    current = os.getpid()
    current_record = next(
        (record for record in records if record.pid == current),
        None,
    )

    if current_record is None:
        print("Current process was not present during /proc scan.")
        return

    print(
        f"Current process: PID={current_record.pid}, "
        f"PPID={current_record.ppid}, Name={current_record.name}"
    )

    parent = current_record.ppid
    print(f"Children directly belonging to PID {parent}:")
    print_process_tree(children, parent, max_depth=2)


def demonstrate_zombie_concept() -> None:
    """
    A zombie is a terminated child whose parent has not yet collected its
    termination status with wait()/waitpid(). The process no longer executes,
    but its exit record remains in the kernel.

    This demonstration intentionally creates a zombie briefly, observes it,
    then reaps it. It does not leave an unreaped process behind.
    """
    heading("Zombie Process")

    child = os.fork()

    if child == 0:
        os._exit(0)

    print(f"Parent PID={os.getpid()} created child PID={child}")
    print("The child exits immediately; parent deliberately waits before reaping.")

    time.sleep(0.4)

    status = parse_proc_status(child)
    state = status.get("State", "process already disappeared")

    print(f"Observed child state: {state}")

    os.waitpid(child, 0)
    print("Parent called waitpid(); zombie state was reaped.")


def demonstrate_process_group() -> None:
    """
    A process group lets related processes receive signals as a unit.

    start_new_session=True creates a new session and process group whose
    initial process has its own PID as the process-group ID. This is useful
    for supervisors that need to terminate a complete subprocess tree.
    """
    heading("Process Groups")

    group_code = r"""
import os
import subprocess
import sys
import time

child_code = r'''
import os
import time
print(f"grandchild PID={os.getpid()} PGID={os.getpgid(0)}", flush=True)
while True:
    time.sleep(0.2)
'''

child = subprocess.Popen(
    [sys.executable, "-c", child_code],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

print(
    f"parent PID={os.getpid()} PGID={os.getpgid(0)} "
    f"child PID={child.pid}",
    flush=True,
)

time.sleep(10)
"""

    process = subprocess.Popen(
        [sys.executable, "-c", group_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    assert process.stdout is not None

    first_line = process.stdout.readline().strip()
    print(first_line)

    print(
        f"Supervisor PID={os.getpid()} will terminate the entire "
        f"process group {process.pid}."
    )

    os.killpg(process.pid, signal.SIGTERM)

    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()

    print(f"Process-group supervisor exit code: {process.returncode}")


def demonstrate_timeout_and_failure() -> None:
    """Show a supervisor pattern for handling a process that exceeds a deadline."""
    heading("Timeout and Failure Handling")

    slow_code = r"""
import time
time.sleep(10)
"""

    process = subprocess.Popen([sys.executable, "-c", slow_code])

    try:
        process.wait(timeout=0.5)
        print("Process finished within the deadline.")
    except subprocess.TimeoutExpired:
        print(f"PID {process.pid} exceeded the deadline.")
        process.terminate()

        try:
            process.wait(timeout=1)
            print("Process stopped after SIGTERM.")
        except subprocess.TimeoutExpired:
            print("SIGTERM did not stop the process; using SIGKILL.")
            process.kill()
            process.wait()

    print(f"Final exit code: {process.returncode}")


def demonstrate_safe_subprocess_execution() -> None:
    """
    Passing an argument list to subprocess.run() avoids shell parsing.

    shell=True should not be used with untrusted strings. The safe pattern is
    to pass the executable and arguments separately whenever possible.
    """
    heading("Safe Subprocess Execution")

    with tempfile.TemporaryDirectory() as directory:
        file_path = Path(directory) / "process-demo.txt"
        file_path.write_text(
            "Linux process supervision\n"
            "PID-oriented diagnostic data\n",
            encoding="utf-8",
        )

        result = subprocess.run(
            ["wc", "-l", str(file_path)],
            capture_output=True,
            text=True,
            check=False,
        )

        print(f"Command exit code: {result.returncode}")
        print(f"Command output: {result.stdout.strip()}")

        if result.returncode != 0:
            print(f"Command failed: {result.stderr.strip()}")


def demonstrate_signal_mask_information() -> None:
    """
    /proc/<pid>/status exposes signal-related bitmasks such as SigBlk,
    SigIgn, and SigCgt. These masks help diagnose why a process may not react
    to a signal as expected.
    """
    heading("Signal State from /proc")

    status = parse_proc_status(os.getpid())

    for field in ("SigQ", "SigPnd", "ShdPnd", "SigBlk", "SigIgn", "SigCgt"):
        print(f"{field:8}: {status.get(field, 'unavailable')}")


def demonstrate_process_states() -> None:
    """
    Linux process states include running/runnable, sleeping, stopped, zombie,
    and several kernel-specific states. The exact state string is kernel-
    dependent, so diagnostics should not assume every possible state exists.
    """
    heading("Process State Observation")

    code = r"""
import os
import time
print(f"PID={os.getpid()}", flush=True)
time.sleep(1.5)
"""

    process = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        text=True,
    )

    assert process.stdout is not None
    print(process.stdout.readline().strip())

    time.sleep(0.2)

    status = parse_proc_status(process.pid)
    print(f"Observed state: {status.get('State', 'unavailable')}")

    process.wait()
    print(f"Process exited with code {process.returncode}")


def demonstrate_exit_statuses() -> None:
    """Explain normal exit, non-zero application failure, and signal death."""
    heading("Exit Status and Failure Semantics")

    successful = subprocess.run(
        [sys.executable, "-c", "raise SystemExit(0)"],
        check=False,
    )
    failed = subprocess.run(
        [sys.executable, "-c", "raise SystemExit(42)"],
        check=False,
    )

    print(f"Normal exit status: {successful.returncode}")
    print(f"Application failure status: {failed.returncode}")

    terminated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(10)"]
    )

    terminated.terminate()
    terminated.wait()

    print(
        "SIGTERM result:",
        terminated.returncode,
        "(negative values in Python indicate termination by a signal)",
    )


def run_all() -> None:
    require_linux()

    show_current_process()
    demonstrate_fork()
    demonstrate_background_process()
    demonstrate_signals()
    demonstrate_process_tree()
    demonstrate_proc_filesystem()
    demonstrate_real_process_tree()
    demonstrate_zombie_concept()
    demonstrate_process_group()
    demonstrate_timeout_and_failure()
    demonstrate_safe_subprocess_execution()
    demonstrate_signal_mask_information()
    demonstrate_process_states()
    demonstrate_exit_statuses()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Linux process laboratory using Python and POSIX process APIs."
    )
    parser.add_argument(
        "--demo",
        choices=(
            "identity",
            "fork",
            "background",
            "signals",
            "tree",
            "proc",
            "real-tree",
            "zombie",
            "groups",
            "timeout",
            "safe-command",
            "signal-state",
            "states",
            "exit-status",
            "all",
        ),
        default="all",
        help="Select a specific process demonstration.",
    )

    args = parser.parse_args()

    demos = {
        "identity": show_current_process,
        "fork": demonstrate_fork,
        "background": demonstrate_background_process,
        "signals": demonstrate_signals,
        "tree": demonstrate_process_tree,
        "proc": demonstrate_proc_filesystem,
        "real-tree": demonstrate_real_process_tree,
        "zombie": demonstrate_zombie_concept,
        "groups": demonstrate_process_group,
        "timeout": demonstrate_timeout_and_failure,
        "safe-command": demonstrate_safe_subprocess_execution,
        "signal-state": demonstrate_signal_mask_information,
        "states": demonstrate_process_states,
        "exit-status": demonstrate_exit_statuses,
        "all": run_all,
    }

    try:
        demos[args.demo]()
    except KeyboardInterrupt:
        print("\nInterrupted by the user.", file=sys.stderr)
        raise SystemExit(130)
    except PermissionError as exc:
        print(f"Permission error while inspecting Linux process state: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
