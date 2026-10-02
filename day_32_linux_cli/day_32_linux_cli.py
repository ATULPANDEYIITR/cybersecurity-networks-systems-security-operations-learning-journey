#!/usr/bin/env python3
"""
Linux CLI: ls, cd, cat, grep, find, awk, sed, pipes, and redirection.

This self-contained script models a realistic Linux CLI investigation workflow
without requiring a Linux machine. It creates a temporary repository-like
workspace and demonstrates the behavior of the requested commands through
Python equivalents, subprocess calls where available, and explicit simulations
of shell pipelines and redirection.

The examples are intentionally centered on repository logs, configuration
files, source files, and operational reports so that each command has a
distinct practical purpose.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


# ---------------------------------------------------------------------------
# Workspace construction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Workspace:
    root: Path
    repository: Path
    logs: Path
    config: Path
    source: Path
    reports: Path


def build_workspace(root: Path) -> Workspace:
    """
    Build a small repository-shaped filesystem.

    The resulting structure gives ls, cd, cat, grep, find, awk, sed, pipes,
    and redirection meaningful input rather than synthetic one-line strings.
    """
    repository = root / "atlas-service"
    logs = repository / "logs"
    config = repository / "config"
    source = repository / "src"
    reports = repository / "reports"

    for directory in (logs, config, source, reports):
        directory.mkdir(parents=True, exist_ok=True)

    (repository / "README.md").write_text(
        "# Atlas Service\n"
        "A small internal service used for demonstrating Linux CLI workflows.\n",
        encoding="utf-8",
    )

    (config / "application.conf").write_text(
        "environment=production\n"
        "port=8080\n"
        "log_level=INFO\n"
        "feature_audit=true\n"
        "feature_cache=true\n",
        encoding="utf-8",
    )

    (config / "database.conf").write_text(
        "host=db.internal\n"
        "port=5432\n"
        "database=atlas\n"
        "pool_size=20\n"
        "ssl=true\n",
        encoding="utf-8",
    )

    (source / "server.py").write_text(
        "def health():\n"
        "    return {\"status\": \"ok\"}\n\n"
        "def authenticate(user):\n"
        "    return user is not None\n",
        encoding="utf-8",
    )

    (source / "parser.py").write_text(
        "def parse_request(payload):\n"
        "    if not payload:\n"
        "        raise ValueError('empty request')\n"
        "    return payload.strip()\n",
        encoding="utf-8",
    )

    (source / "metrics.py").write_text(
        "def record_latency(milliseconds):\n"
        "    if milliseconds < 0:\n"
        "        raise ValueError('latency cannot be negative')\n"
        "    return milliseconds\n",
        encoding="utf-8",
    )

    (logs / "application.log").write_text(
        "2026-10-02T06:00:02Z INFO request id=1001 route=/health latency_ms=18\n"
        "2026-10-02T06:00:05Z INFO request id=1002 route=/orders latency_ms=91\n"
        "2026-10-02T06:00:08Z WARN request id=1003 route=/orders latency_ms=240\n"
        "2026-10-02T06:00:11Z ERROR request id=1004 route=/orders latency_ms=901\n"
        "2026-10-02T06:00:14Z INFO request id=1005 route=/health latency_ms=16\n"
        "2026-10-02T06:00:17Z ERROR request id=1006 route=/payments latency_ms=1200\n",
        encoding="utf-8",
    )

    (logs / "security.log").write_text(
        "2026-10-02T06:01:00Z INFO login user=alice source=10.0.0.8\n"
        "2026-10-02T06:01:04Z WARN login user=bob source=10.0.0.9\n"
        "2026-10-02T06:01:09Z ERROR login user=bob source=10.0.0.9 reason=invalid_password\n"
        "2026-10-02T06:01:20Z INFO login user=carol source=10.0.0.10\n",
        encoding="utf-8",
    )

    (reports / "deployments.csv").write_text(
        "service,environment,status,duration_seconds\n"
        "atlas-api,production,success,84\n"
        "atlas-worker,production,success,121\n"
        "atlas-web,production,failed,47\n"
        "atlas-scheduler,staging,success,33\n",
        encoding="utf-8",
    )

    return Workspace(root, repository, logs, config, source, reports)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def heading(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def show_lines(lines: Iterable[str]) -> None:
    for line in lines:
        print(line)


def run_command(command: Sequence[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """
    Execute an external command safely.

    Arguments are passed as a list rather than through shell=True. This avoids
    accidental shell interpretation and is the safer choice when input can
    originate outside the program.
    """
    return subprocess.run(
        list(command),
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def command_available(name: str) -> bool:
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

def demo_ls(workspace: Workspace) -> None:
    heading("ls: inspect directory contents")

    print("Basic listing of the repository:")
    for entry in sorted(workspace.repository.iterdir(), key=lambda p: p.name):
        print(entry.name)

    print("\nLong-style information:")
    for entry in sorted(workspace.repository.iterdir(), key=lambda p: p.name):
        kind = "d" if entry.is_dir() else "-"
        size = entry.stat().st_size if entry.is_file() else 0
        print(f"{kind} {size:>8} {entry.name}")

    print("\nRecursive listing equivalent to a focused ls -R:")
    for path in sorted(workspace.repository.rglob("*")):
        relative = path.relative_to(workspace.repository)
        print(relative)


# ---------------------------------------------------------------------------
# cd
# ---------------------------------------------------------------------------

def demo_cd(workspace: Workspace) -> None:
    heading("cd: change the shell's working directory")

    original = Path.cwd()
    print(f"Starting directory: {original}")

    try:
        os.chdir(workspace.repository)
        print(f"After cd atlas-service: {Path.cwd()}")

        os.chdir("logs")
        print(f"After cd logs: {Path.cwd()}")

        os.chdir("..")
        print(f"After cd ..: {Path.cwd()}")

        os.chdir(workspace.config)
        print(f"After cd to config: {Path.cwd()}")
    finally:
        os.chdir(original)

    print(
        "\nA shell's cd changes the working directory of that shell process. "
        "A child process cannot normally change the parent shell's directory."
    )


# ---------------------------------------------------------------------------
# cat
# ---------------------------------------------------------------------------

def demo_cat(workspace: Workspace) -> None:
    heading("cat: read and concatenate files")

    application = workspace.config / "application.conf"
    database = workspace.config / "database.conf"

    print("Reading application.conf:")
    print(application.read_text(encoding="utf-8"), end="")

    print("\nConcatenating two configuration files:")
    for path in (application, database):
        print(f"# {path.name}")
        print(path.read_text(encoding="utf-8"), end="")

    print("\nThe cat command is useful for small files. For very large files,")
    print("paging tools such as less are generally more appropriate.")


# ---------------------------------------------------------------------------
# grep
# ---------------------------------------------------------------------------

def grep(
    pattern: str,
    paths: Iterable[Path],
    *,
    ignore_case: bool = False,
    recursive: bool = False,
) -> list[str]:
    """
    A small grep-like implementation.

    Each result contains the path, line number, and matching line. A regular
    expression is used because grep commonly supports regex-based searching.
    """
    flags = re.IGNORECASE if ignore_case else 0
    expression = re.compile(pattern, flags)
    results: list[str] = []

    candidate_paths: list[Path] = []

    for path in paths:
        if path.is_file():
            candidate_paths.append(path)
        elif recursive and path.is_dir():
            candidate_paths.extend(p for p in path.rglob("*") if p.is_file())

    for path in candidate_paths:
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if expression.search(line):
                        results.append(
                            f"{path}:{line_number}:{line.rstrip()}"
                        )
        except UnicodeDecodeError:
            # Real grep may inspect binary data differently. This simulation
            # deliberately skips files that are not valid UTF-8 text.
            continue

    return results


def demo_grep(workspace: Workspace) -> None:
    heading("grep: search text inside files")

    print("Find ERROR records in application.log:")
    show_lines(
        grep(
            r"\bERROR\b",
            [workspace.logs / "application.log"],
        )
    )

    print("\nCase-insensitive search for login failures:")
    show_lines(
        grep(
            r"invalid_password",
            [workspace.logs],
            ignore_case=True,
            recursive=True,
        )
    )

    print("\nSearch source files for ValueError:")
    show_lines(
        grep(
            r"ValueError",
            [workspace.source],
            recursive=True,
        )
    )

    print(
        "\ngrep is a search operation. It does not normally understand the "
        "semantic structure of a CSV or configuration file; it matches text."
    )


# ---------------------------------------------------------------------------
# find
# ---------------------------------------------------------------------------

def demo_find(workspace: Workspace) -> None:
    heading("find: locate files using filesystem predicates")

    print("Find all Python files:")
    for path in sorted(workspace.repository.rglob("*.py")):
        print(path.relative_to(workspace.repository))

    print("\nFind configuration files:")
    for path in sorted(workspace.repository.rglob("*.conf")):
        print(path.relative_to(workspace.repository))

    print("\nFind log files larger than zero bytes:")
    for path in sorted(workspace.logs.rglob("*")):
        if path.is_file() and path.stat().st_size > 0:
            print(f"{path.relative_to(workspace.repository)} {path.stat().st_size} bytes")

    print(
        "\nfind searches the filesystem tree. It answers 'where are the "
        "matching paths?', while grep answers 'which lines contain this text?'"
    )


# ---------------------------------------------------------------------------
# awk
# ---------------------------------------------------------------------------

def awk_like_latency_report(log_file: Path) -> list[str]:
    """
    Model an awk-style field-processing operation.

    The log format has whitespace-separated fields. awk is especially useful
    when a line can be treated as records and columns without writing a full
    parser.
    """
    output = ["request_id route latency_ms"]

    with log_file.open(encoding="utf-8") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 5:
                continue

            level = fields[1]
            request_id = fields[2].split("=", 1)[1]
            route = fields[3].split("=", 1)[1]
            latency = int(fields[4].split("=", 1)[1])

            if level in {"WARN", "ERROR"}:
                output.append(f"{request_id} {route} {latency}")

    return output


def demo_awk(workspace: Workspace) -> None:
    heading("awk: process records and fields")

    report = awk_like_latency_report(workspace.logs / "application.log")
    show_lines(report)

    print("\nCompute average latency from the log records:")
    latencies: list[int] = []

    with (workspace.logs / "application.log").open(encoding="utf-8") as handle:
        for line in handle:
            match = re.search(r"\blatency_ms=(\d+)", line)
            if match:
                latencies.append(int(match.group(1)))

    average = sum(latencies) / len(latencies)
    print(f"records={len(latencies)} average_latency_ms={average:.2f}")

    print(
        "\nawk is especially strong when the input is line-oriented and "
        "field-oriented: select records, transform columns, aggregate values, "
        "and print a derived report."
    )


# ---------------------------------------------------------------------------
# sed
# ---------------------------------------------------------------------------

def sed_substitute(text: str, pattern: str, replacement: str) -> str:
    """Apply a controlled regex substitution similar to sed's s/// operation."""
    return re.sub(pattern, replacement, text)


def demo_sed(workspace: Workspace) -> None:
    heading("sed: transform streams of text")

    source = (workspace.config / "application.conf").read_text(encoding="utf-8")

    print("Original configuration:")
    print(source, end="")

    transformed = sed_substitute(
        source,
        r"^log_level=.*$",
        "log_level=DEBUG",
    )

    print("\nTransformed configuration:")
    print(transformed, end="")

    print(
        "\nThe example changes only the matching configuration line. A production "
        "sed command should be tested before modifying important configuration."
    )


# ---------------------------------------------------------------------------
# Pipes
# ---------------------------------------------------------------------------

def pipeline(
    producer: Iterable[str],
    *stages,
) -> list[str]:
    """
    A Python representation of a Unix pipeline.

    Every stage consumes an iterable and returns another iterable. This mirrors
    the conceptual Unix pipeline: stdout from one process becomes stdin of the
    next process.
    """
    current = producer
    for stage in stages:
        current = stage(current)
    return list(current)


def stage_select_error(lines: Iterable[str]) -> Iterable[str]:
    return (line for line in lines if "ERROR" in line)


def stage_extract_route(lines: Iterable[str]) -> Iterable[str]:
    for line in lines:
        match = re.search(r"route=([^\s]+)", line)
        if match:
            yield match.group(1)


def stage_unique(lines: Iterable[str]) -> Iterable[str]:
    seen: set[str] = set()
    for line in lines:
        if line not in seen:
            seen.add(line)
            yield line


def demo_pipes(workspace: Workspace) -> None:
    heading("pipes: compose independent transformations")

    lines = (
        workspace.logs / "application.log"
    ).read_text(encoding="utf-8").splitlines()

    result = pipeline(
        lines,
        stage_select_error,
        stage_extract_route,
        stage_unique,
    )

    print("Conceptual pipeline:")
    print("application.log | grep ERROR | extract route | unique")
    print("\nResult:")
    show_lines(result)

    print(
        "\nUnix pipes normally connect process stdout to the next process's stdin. "
        "This allows small programs to be combined instead of requiring one "
        "large program to implement every transformation."
    )


# ---------------------------------------------------------------------------
# Redirection
# ---------------------------------------------------------------------------

def demo_redirection(workspace: Workspace) -> None:
    heading("redirection: capture command output")

    report = workspace.reports / "error-routes.txt"

    lines = (workspace.logs / "application.log").read_text(
        encoding="utf-8"
    ).splitlines()

    errors = [line for line in lines if "ERROR" in line]
    routes = []

    for line in errors:
        match = re.search(r"route=([^\s]+)", line)
        if match:
            routes.append(match.group(1))

    # This is the file equivalent of stdout > error-routes.txt.
    report.write_text("\n".join(routes) + "\n", encoding="utf-8")

    print(f"Created {report.name} using output redirection semantics.")
    print(report.read_text(encoding="utf-8"), end="")

    # Appending corresponds conceptually to >> rather than replacing the file.
    with report.open("a", encoding="utf-8") as handle:
        handle.write("/audit\n")

    print("After append-style redirection:")
    print(report.read_text(encoding="utf-8"), end="")

    print(
        "\nThe important distinction is that > replaces the destination while "
        ">> appends to it. Shell redirection occurs before the command executes."
    )


# ---------------------------------------------------------------------------
# Integrated workflow
# ---------------------------------------------------------------------------

def integrated_investigation(workspace: Workspace) -> None:
    heading("Integrated Linux CLI investigation")

    log = workspace.logs / "application.log"

    print("Goal: identify slow requests, isolate their routes, and write a report.")

    records = log.read_text(encoding="utf-8").splitlines()

    # Equivalent conceptual shell flow:
    #
    # cat logs/application.log |
    # grep -E 'WARN|ERROR' |
    # awk '{...}' |
    # sed '...'
    #
    # The Python implementation keeps each operation explicit so the data flow
    # can be inspected and tested.
    suspicious = [
        line for line in records
        if re.search(r"\b(WARN|ERROR)\b", line)
    ]

    extracted: list[str] = []
    for line in suspicious:
        route = re.search(r"route=([^\s]+)", line)
        latency = re.search(r"latency_ms=(\d+)", line)
        if route and latency:
            extracted.append(
                f"{route.group(1)},{int(latency.group(1))}"
            )

    report_path = workspace.reports / "slow-requests.csv"
    with report_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["route", "latency_ms"])
        for record in extracted:
            route, latency = record.split(",", 1)
            writer.writerow([route, int(latency)])

    print(f"Report written to: {report_path}")
    print(report_path.read_text(encoding="utf-8"), end="")

    print(
        "\nThe workflow demonstrates the key distinction between locating files "
        "with find, matching text with grep, transforming fields with awk, "
        "rewriting text with sed, connecting stages with pipes, and persisting "
        "stdout with redirection."
    )


# ---------------------------------------------------------------------------
# Real command execution when Linux utilities are available
# ---------------------------------------------------------------------------

def demo_real_commands(workspace: Workspace) -> None:
    heading("Real CLI commands when available")

    commands = [
        ["ls", "-la"],
        ["find", ".", "-type", "f", "-name", "*.log"],
        ["grep", "-n", "ERROR", "logs/application.log"],
        ["awk", "{print $2, $3, $5}", "logs/application.log"],
        ["sed", "s/^log_level=.*/log_level=DEBUG/", "config/application.conf"],
    ]

    for command in commands:
        executable = command[0]

        if not command_available(executable):
            print(f"$ {' '.join(command)}")
            print(f"{executable}: command not available in this environment")
            continue

        print(f"\n$ {' '.join(command)}")
        result = run_command(command, cwd=workspace.repository)

        if result.stdout:
            print(result.stdout, end="")

        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)

        print(f"[exit status: {result.returncode}]")

    print(
        "\nThe Python program never needs shell=True for these commands. Passing "
        "argument lists preserves argument boundaries and avoids shell injection "
        "risks that can arise from interpolating untrusted strings into shell code."
    )


# ---------------------------------------------------------------------------
# Validation and edge cases
# ---------------------------------------------------------------------------

def demonstrate_edge_cases(workspace: Workspace) -> None:
    heading("Edge cases and failure conditions")

    missing = workspace.repository / "does-not-exist.txt"

    print("cat-like read of a missing file:")
    try:
        missing.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        print(f"handled FileNotFoundError: {exc}")

    print("\nInvalid regular expression passed to grep-like search:")
    try:
        re.compile("[")
    except re.error as exc:
        print(f"handled regex error: {exc}")

    print("\nEmpty directory search:")
    empty = workspace.repository / "empty"
    empty.mkdir(exist_ok=True)
    matches = list(empty.rglob("*"))
    print(f"matches={len(matches)}")

    print("\nAwk-like malformed record:")
    malformed = "not-enough-fields"
    fields = malformed.split()
    if len(fields) < 5:
        print("record skipped because the expected fields are absent")

    print("\nSed-like substitution with no match:")
    original = "port=8080\n"
    changed = sed_substitute(original, r"^missing=.*$", "missing=true")
    print(f"unchanged={changed == original}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demonstrate Linux CLI concepts with a repository-style workspace."
    )
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="Keep the generated temporary workspace after execution.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    temporary_directory = tempfile.TemporaryDirectory(prefix="linux-cli-lab-")
    root = Path(temporary_directory.name)

    try:
        workspace = build_workspace(root)

        print(f"Linux CLI learning workspace: {workspace.repository}")

        demo_ls(workspace)
        demo_cd(workspace)
        demo_cat(workspace)
        demo_grep(workspace)
        demo_find(workspace)
        demo_awk(workspace)
        demo_sed(workspace)
        demo_pipes(workspace)
        demo_redirection(workspace)
        integrated_investigation(workspace)
        demonstrate_edge_cases(workspace)
        demo_real_commands(workspace)

        print("\nCLI demonstration completed successfully.")

        if args.keep_workspace:
            persistent = Path.cwd() / "linux-cli-lab-output"
            if persistent.exists():
                shutil.rmtree(persistent)
            shutil.copytree(workspace.repository, persistent)
            print(f"Workspace copied to: {persistent}")

        return 0

    except (OSError, ValueError, csv.Error) as exc:
        print(f"Fatal demonstration error: {exc}", file=sys.stderr)
        return 1

    finally:
        temporary_directory.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
