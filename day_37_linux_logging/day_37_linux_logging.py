#!/usr/bin/env python3
"""
Linux Logging Laboratory

A self-contained demonstration of Linux logging concepts using Python's
standard library. The program works with common Linux log locations when
they exist, while also providing a safe simulation mode so it remains
executable on systems without systemd or Linux log files.

Topics covered:
- syslog-style facilities and severity levels
- journald and journalctl concepts
- authentication logs
- kernel logs
- application logs
- structured log parsing
- filtering and correlation
- log rotation
- suspicious-event detection
- secure logging practices
- operational reporting
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import logging.handlers
import os
import re
import socket
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional


SEVERITIES = {
    "emerg": 0,
    "alert": 1,
    "crit": 2,
    "err": 3,
    "warning": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}

FACILITIES = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}


@dataclass
class LogRecord:
    timestamp: datetime
    host: str
    service: str
    facility: str
    severity: str
    message: str
    source: str
    pid: Optional[int] = None
    user: Optional[str] = None
    ip: Optional[str] = None
    raw: str = ""

    @property
    def priority(self) -> int:
        return FACILITIES.get(self.facility, 1) * 8 + SEVERITIES.get(
            self.severity, 6
        )

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "service": self.service,
            "facility": self.facility,
            "severity": self.severity,
            "message": self.message,
            "source": self.source,
            "pid": self.pid,
            "user": self.user,
            "ip": self.ip,
        }


class LogParser:
    """Parses common syslog, authentication, kernel, and JSON application logs."""

    SYSLOG_RE = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<tag>[^:\[]+)"
        r"(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)$"
    )

    SSH_RE = re.compile(
        r"(?P<action>Accepted|Failed|Invalid user)\s+"
        r"(?:password|publickey|keyboard-interactive/pam)?"
        r"(?: for (?:invalid user )?(?P<user>\S+))?.*?"
        r"from\s+(?P<ip>[0-9a-fA-F:.]+)"
    )

    KERNEL_RE = re.compile(
        r"(?:\[\s*(?P<uptime>\d+\.\d+)\]\s*)?"
        r"(?P<message>.*)"
    )

    def __init__(self, hostname: Optional[str] = None):
        self.hostname = hostname or socket.gethostname()

    def parse_syslog_line(
        self,
        line: str,
        source: str,
        year: Optional[int] = None,
    ) -> Optional[LogRecord]:
        match = self.SYSLOG_RE.match(line.strip())
        if not match:
            return None

        now = datetime.now()
        year = year or now.year

        try:
            timestamp = datetime.strptime(
                f"{year} {match.group('month')} {match.group('day')} "
                f"{match.group('time')}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return None

        tag = match.group("tag").strip()
        message = match.group("message").strip()

        facility = "authpriv" if tag in {"sshd", "sudo", "su"} else "daemon"
        severity = self._infer_severity(message)

        record = LogRecord(
            timestamp=timestamp,
            host=match.group("host"),
            service=tag,
            facility=facility,
            severity=severity,
            message=message,
            source=source,
            pid=int(match.group("pid")) if match.group("pid") else None,
            raw=line.rstrip(),
        )

        ssh_match = self.SSH_RE.search(message)
        if ssh_match:
            record.user = ssh_match.group("user")
            record.ip = ssh_match.group("ip")

        return record

    def parse_json_application_log(
        self,
        line: str,
        source: str,
    ) -> Optional[LogRecord]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return None

        timestamp_text = item.get("timestamp") or item.get("time")
        if not timestamp_text:
            timestamp = datetime.now(timezone.utc)
        else:
            try:
                timestamp = datetime.fromisoformat(
                    timestamp_text.replace("Z", "+00:00")
                )
            except ValueError:
                timestamp = datetime.now(timezone.utc)

        level = str(item.get("level", "INFO")).lower()
        severity_map = {
            "fatal": "emerg",
            "error": "err",
            "warn": "warning",
            "trace": "debug",
        }

        severity = severity_map.get(level, level)
        if severity not in SEVERITIES:
            severity = "info"

        return LogRecord(
            timestamp=timestamp,
            host=item.get("host", self.hostname),
            service=item.get("service", "application"),
            facility=item.get("facility", "local0"),
            severity=severity,
            message=str(item.get("message", "")),
            source=source,
            pid=item.get("pid"),
            user=item.get("user"),
            ip=item.get("ip"),
            raw=line.rstrip(),
        )

    @staticmethod
    def _infer_severity(message: str) -> str:
        lowered = message.lower()

        if any(word in lowered for word in ("kernel panic", "emergency")):
            return "emerg"
        if any(word in lowered for word in ("critical", "panic")):
            return "crit"
        if any(word in lowered for word in ("error", "failed", "failure")):
            return "err"
        if any(word in lowered for word in ("warning", "warn")):
            return "warning"
        return "info"


class JournalReader:
    """Reads journald through journalctl when systemd-journald is available."""

    def __init__(self, parser: LogParser):
        self.parser = parser

    def available(self) -> bool:
        return (
            sys.platform.startswith("linux")
            and subprocess.run(
                ["sh", "-c", "command -v journalctl >/dev/null 2>&1"],
                capture_output=True,
                check=False,
            ).returncode
            == 0
        )

    def read_recent(self, lines: int = 20) -> list[LogRecord]:
        if not self.available():
            return []

        command = [
            "journalctl",
            "-n",
            str(lines),
            "--no-pager",
            "-o",
            "json",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return []

        records: list[LogRecord] = []

        for line in result.stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            timestamp = self._journal_timestamp(item.get("__REALTIME_TIMESTAMP"))
            priority = int(item.get("PRIORITY", 6))
            facility_number = int(item.get("SYSLOG_FACILITY", 3))

            facility = next(
                (
                    name
                    for name, value in FACILITIES.items()
                    if value == facility_number
                ),
                "daemon",
            )

            severity = next(
                (
                    name
                    for name, value in SEVERITIES.items()
                    if value == priority
                ),
                "info",
            )

            service = (
                item.get("_SYSTEMD_UNIT")
                or item.get("SYSLOG_IDENTIFIER")
                or "systemd"
            )

            records.append(
                LogRecord(
                    timestamp=timestamp,
                    host=item.get("_HOSTNAME", self.parser.hostname),
                    service=service,
                    facility=facility,
                    severity=severity,
                    message=str(item.get("MESSAGE", "")),
                    source="journald",
                    pid=self._integer(item.get("_PID")),
                    user=None,
                    ip=None,
                )
            )

        return records

    @staticmethod
    def _journal_timestamp(value: object) -> datetime:
        try:
            microseconds = int(value)
            return datetime.fromtimestamp(
                microseconds / 1_000_000,
                tz=timezone.utc,
            )
        except (TypeError, ValueError, OSError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _integer(value: object) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


class AuthenticationAnalyzer:
    """Finds SSH authentication failures and successful sessions."""

    FAILURE_RE = re.compile(
        r"(?:Failed password|authentication failure|Invalid user)"
        r".*?(?:from\s+)?(?P<ip>[0-9a-fA-F:.]+)?",
        re.IGNORECASE,
    )

    SUCCESS_RE = re.compile(
        r"Accepted .*? for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)",
        re.IGNORECASE,
    )

    def analyze(self, records: Iterable[LogRecord]) -> dict:
        failures_by_ip: Counter[str] = Counter()
        successes_by_user: Counter[str] = Counter()

        for record in records:
            if record.service not in {"sshd", "ssh"}:
                continue

            if "Failed password" in record.message or "Invalid user" in record.message:
                ip = record.ip or self._extract_ip(record.message)
                if ip:
                    failures_by_ip[ip] += 1

            success = self.SUCCESS_RE.search(record.message)
            if success:
                successes_by_user[success.group("user")] += 1

        suspicious_ips = {
            ip: count
            for ip, count in failures_by_ip.items()
            if count >= 3
        }

        return {
            "failed_attempts_by_ip": dict(failures_by_ip),
            "successful_users": dict(successes_by_user),
            "suspicious_ips": suspicious_ips,
        }

    @staticmethod
    def _extract_ip(message: str) -> Optional[str]:
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        return match.group(0) if match else None


class KernelAnalyzer:
    """Classifies kernel messages into useful operational categories."""

    KEYWORDS = {
        "memory": ("oom", "out of memory", "memory"),
        "storage": ("i/o error", "filesystem", "ext4", "xfs", "nvme"),
        "network": ("link is down", "link is up", "network"),
        "hardware": ("thermal", "cpu", "hardware", "firmware"),
        "security": ("apparmor", "selinux", "audit", "denied"),
    }

    def classify(self, records: Iterable[LogRecord]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = defaultdict(list)

        for record in records:
            if record.facility != "kern" and record.service not in {
                "kernel",
                "kernel:kernel",
            }:
                continue

            lowered = record.message.lower()
            matched = False

            for category, keywords in self.KEYWORDS.items():
                if any(keyword in lowered for keyword in keywords):
                    result[category].append(record.message)
                    matched = True

            if not matched:
                result["other"].append(record.message)

        return dict(result)


class LogCorrelator:
    """Correlates authentication and application events by time and IP."""

    def correlate(
        self,
        records: list[LogRecord],
        window_seconds: int = 120,
    ) -> list[dict]:
        auth_failures = [
            record
            for record in records
            if record.service == "sshd"
            and "Failed password" in record.message
            and record.ip
        ]

        application_events = [
            record
            for record in records
            if record.service not in {"sshd", "kernel"}
            and record.ip
        ]

        correlations = []

        for failure in auth_failures:
            for event in application_events:
                if failure.ip != event.ip:
                    continue

                delta = abs(
                    (event.timestamp - failure.timestamp).total_seconds()
                )

                if delta <= window_seconds:
                    correlations.append(
                        {
                            "ip": failure.ip,
                            "authentication_event": failure.message,
                            "application_event": event.message,
                            "seconds_apart": round(delta, 2),
                        }
                    )

        return correlations


class ApplicationLogger:
    """Configures an application logger with rotation and structured output."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.logger = logging.getLogger("linux_logging_demo")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10_000,
            backupCount=3,
            encoding="utf-8",
        )

        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s "
            "pid=%(process)d %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def record_login_attempt(
        self,
        username: str,
        ip: str,
        success: bool,
    ) -> None:
        # Never log passwords, session tokens, authorization headers,
        # or other credentials. Username and source IP are operational
        # attributes that may still require access controls and retention rules.
        status = "success" if success else "failure"
        self.logger.info(
            "authentication_attempt user=%s ip=%s result=%s",
            username,
            ip,
            status,
        )


class LinuxLogLocator:
    """Identifies conventional Linux log sources without assuming they exist."""

    CANDIDATES = {
        "syslog": [
            Path("/var/log/syslog"),
            Path("/var/log/messages"),
        ],
        "authentication": [
            Path("/var/log/auth.log"),
            Path("/var/log/secure"),
        ],
        "kernel": [
            Path("/var/log/kern.log"),
        ],
    }

    def discover(self) -> dict[str, list[Path]]:
        discovered: dict[str, list[Path]] = {}

        for category, paths in self.CANDIDATES.items():
            discovered[category] = [
                path for path in paths if path.is_file()
            ]

        return discovered


def create_simulated_records() -> list[LogRecord]:
    """Creates realistic records for systems without accessible Linux logs."""
    base = datetime.now(timezone.utc).replace(microsecond=0)

    raw_records = [
        (
            0,
            "server01",
            "sshd",
            "authpriv",
            "warning",
            "Failed password for invalid user admin from 203.0.113.42 port 44221 ssh2",
            "auth.log",
            None,
            None,
            "203.0.113.42",
        ),
        (
            15,
            "server01",
            "sshd",
            "authpriv",
            "warning",
            "Failed password for root from 203.0.113.42 port 44222 ssh2",
            "auth.log",
            None,
            "root",
            "203.0.113.42",
        ),
        (
            30,
            "server01",
            "sshd",
            "authpriv",
            "info",
            "Accepted publickey for deploy from 10.10.20.15 port 51000 ssh2",
            "auth.log",
            None,
            "deploy",
            "10.10.20.15",
        ),
        (
            45,
            "server01",
            "kernel",
            "kern",
            "err",
            "nvme0: I/O error, aborting command",
            "kern.log",
            None,
            None,
            None,
        ),
        (
            60,
            "server01",
            "kernel",
            "kern",
            "warning",
            "Out of memory: Kill process 2481 (worker)",
            "kern.log",
            2481,
            None,
            None,
        ),
        (
            75,
            "server01",
            "inventory-api",
            "local0",
            "err",
            "database connection pool exhausted",
            "application.log",
            4120,
            None,
            "203.0.113.42",
        ),
        (
            90,
            "server01",
            "inventory-api",
            "local0",
            "info",
            "request completed method=GET path=/health status=200",
            "application.log",
            4120,
            None,
            "10.10.20.15",
        ),
    ]

    return [
        LogRecord(
            timestamp=base + timedelta(seconds=offset),
            host=host,
            service=service,
            facility=facility,
            severity=severity,
            message=message,
            source=source,
            pid=pid,
            user=user,
            ip=ip,
        )
        for (
            offset,
            host,
            service,
            facility,
            severity,
            message,
            source,
            pid,
            user,
            ip,
        ) in raw_records
    ]


def read_text_log(
    path: Path,
    parser: LogParser,
    limit: int = 500,
) -> list[LogRecord]:
    records = []

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= limit:
                    break

                record = parser.parse_syslog_line(
                    line,
                    source=str(path),
                )
                if record:
                    records.append(record)
    except PermissionError:
        print(f"Permission denied: {path}")
    except OSError as exc:
        print(f"Unable to read {path}: {exc}")

    return records


def demonstrate_syslog_priority() -> None:
    print("\nSYSLOG PRIORITY MODEL")
    print("-" * 60)

    examples = [
        ("authpriv", "warning"),
        ("kern", "err"),
        ("local0", "info"),
    ]

    for facility, severity in examples:
        priority = FACILITIES[facility] * 8 + SEVERITIES[severity]
        print(
            f"facility={facility:<9} severity={severity:<8} "
            f"numeric_priority={priority}"
        )

    print(
        "\nA syslog priority combines facility and severity as "
        "facility * 8 + severity. The facility identifies the subsystem; "
        "the severity expresses urgency."
    )


def demonstrate_application_logging() -> None:
    print("\nAPPLICATION LOGGING")
    print("-" * 60)

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "application.log"
        logger = ApplicationLogger(path)

        logger.record_login_attempt(
            username="analyst",
            ip="192.0.2.10",
            success=True,
        )
        logger.record_login_attempt(
            username="unknown",
            ip="203.0.113.99",
            success=False,
        )

        print(path.read_text(encoding="utf-8").rstrip())

        print(
            "\nThe RotatingFileHandler limits individual file size and keeps "
            "backup files, preventing an application log from consuming "
            "unbounded disk space."
        )


def demonstrate_compression() -> None:
    print("\nLOG ROTATION AND COMPRESSION")
    print("-" * 60)

    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "application.log"
        compressed = Path(directory) / "application.log.1.gz"

        source.write_text(
            "2026-10-07T16:00:00+00:00 INFO service started\n"
            "2026-10-07T16:01:00+00:00 INFO request completed\n",
            encoding="utf-8",
        )

        with source.open("rb") as input_file, gzip.open(
            compressed,
            "wb",
        ) as output_file:
            output_file.write(input_file.read())

        print(
            f"Created {compressed.name}: "
            f"{compressed.stat().st_size} bytes"
        )


def demonstrate_journald(reader: JournalReader) -> None:
    print("\nJOURNALD")
    print("-" * 60)

    if not reader.available():
        print(
            "journalctl is unavailable. On a systemd host, journald normally "
            "collects kernel, service, authentication, and application events "
            "and journalctl provides the query interface."
        )
        return

    records = reader.read_recent(lines=10)

    if not records:
        print(
            "journalctl is available, but no readable recent records were "
            "returned."
        )
        return

    for record in records:
        print(
            f"{record.timestamp.isoformat()} "
            f"{record.service:<20} "
            f"{record.severity:<8} "
            f"{record.message[:100]}"
        )


def demonstrate_security(records: list[LogRecord]) -> None:
    print("\nSECURITY-RELEVANT LOG ANALYSIS")
    print("-" * 60)

    analyzer = AuthenticationAnalyzer()
    result = analyzer.analyze(records)

    print("Failed authentication attempts:")
    for ip, count in result["failed_attempts_by_ip"].items():
        print(f"  {ip}: {count}")

    print("Successful accounts:")
    for user, count in result["successful_users"].items():
        print(f"  {user}: {count}")

    print("Potentially suspicious sources:")
    for ip, count in result["suspicious_ips"].items():
        print(f"  {ip}: {count} failures")

    print(
        "\nA log record is evidence, not proof of an intrusion. Correlation "
        "with identity, network, process, and host telemetry is required "
        "before treating an event as a confirmed security incident."
    )


def demonstrate_kernel_analysis(records: list[LogRecord]) -> None:
    print("\nKERNEL LOG ANALYSIS")
    print("-" * 60)

    analyzer = KernelAnalyzer()
    categories = analyzer.classify(records)

    for category, messages in categories.items():
        print(f"[{category}]")
        for message in messages:
            print(f"  {message}")


def demonstrate_correlation(records: list[LogRecord]) -> None:
    print("\nCROSS-SOURCE CORRELATION")
    print("-" * 60)

    correlations = LogCorrelator().correlate(records)

    if not correlations:
        print("No authentication/application correlations detected.")
        return

    for item in correlations:
        print(
            f"IP {item['ip']} produced an authentication failure and an "
            f"application event {item['seconds_apart']} seconds apart."
        )
        print(f"  auth: {item['authentication_event']}")
        print(f"  app : {item['application_event']}")


def demonstrate_parsing(parser: LogParser) -> None:
    print("\nPARSING EXAMPLES")
    print("-" * 60)

    syslog_line = (
        "Oct  7 16:30:22 server01 sshd[7124]: "
        "Failed password for root from 203.0.113.42 port 4422 ssh2"
    )

    record = parser.parse_syslog_line(syslog_line, "auth.log")
    if record:
        print(json.dumps(record.as_dict(), indent=2))

    json_line = json.dumps(
        {
            "timestamp": "2026-10-07T16:31:00+00:00",
            "level": "ERROR",
            "service": "payments-api",
            "message": "request rejected",
            "ip": "192.0.2.44",
            "pid": 812,
        }
    )

    application_record = parser.parse_json_application_log(
        json_line,
        "payments.json.log",
    )

    if application_record:
        print(json.dumps(application_record.as_dict(), indent=2))


def discover_real_logs(
    locator: LinuxLogLocator,
    parser: LogParser,
) -> list[LogRecord]:
    records = []

    discovered = locator.discover()

    for category, paths in discovered.items():
        print(f"\n{category.upper()} LOG SOURCES")

        if not paths:
            print("  No conventional text log found.")
            continue

        for path in paths:
            print(f"  {path}")
            records.extend(read_text_log(path, parser))

    return records


def build_report(records: list[LogRecord]) -> None:
    print("\nLOGGING REPORT")
    print("-" * 60)

    by_source = Counter(record.source for record in records)
    by_severity = Counter(record.severity for record in records)
    by_service = Counter(record.service for record in records)

    print(f"Total records: {len(records)}")

    print("\nSources:")
    for source, count in by_source.most_common():
        print(f"  {source}: {count}")

    print("\nSeverities:")
    for severity, count in sorted(
        by_severity.items(),
        key=lambda item: SEVERITIES.get(item[0], 99),
    ):
        print(f"  {severity}: {count}")

    print("\nServices:")
    for service, count in by_service.most_common():
        print(f"  {service}: {count}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Linux logging demonstration and analysis tool"
    )
    parser.add_argument(
        "--real-logs",
        action="store_true",
        help="Read conventional Linux text logs when accessible.",
    )
    parser.add_argument(
        "--journal",
        action="store_true",
        help="Query recent journald entries through journalctl.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    parser = LogParser()
    journal = JournalReader(parser)
    locator = LinuxLogLocator()

    print("LINUX LOGGING LABORATORY")
    print("=" * 60)
    print(f"Host: {socket.gethostname()}")
    print(f"Platform: {sys.platform}")

    demonstrate_syslog_priority()
    demonstrate_parsing(parser)
    demonstrate_application_logging()
    demonstrate_compression()

    if args.real_logs:
        records = discover_real_logs(locator, parser)
        if not records:
            print(
                "\nNo conventional readable text logs were found. "
                "Using simulated records for the analysis demonstrations."
            )
            records = create_simulated_records()
    else:
        records = create_simulated_records()
        print(
            "\nUsing simulated records. Pass --real-logs to inspect "
            "accessible conventional Linux log files."
        )

    demonstrate_security(records)
    demonstrate_kernel_analysis(records)
    demonstrate_correlation(records)
    build_report(records)

    if args.journal:
        demonstrate_journald(journal)
    else:
        print(
            "\nPass --journal to query recent journald entries when "
            "journalctl is available."
        )

    print("\nOperational note:")
    print(
        "Linux logging is normally distributed across logging layers. "
        "syslog semantics describe facilities and severities, journald "
        "stores structured journal entries on systemd systems, traditional "
        "authentication and kernel logs provide focused evidence, and "
        "application logs carry service-specific context."
    )


if __name__ == "__main__":
    main()
