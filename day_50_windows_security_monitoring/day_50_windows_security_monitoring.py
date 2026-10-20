from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


WINDOWS_EVENT_IDS = {
    4624: "successful_logon",
    4625: "failed_logon",
    4634: "logoff",
    4647: "user_initiated_logoff",
    4672: "special_privileges_assigned",
    4688: "process_created",
    4720: "account_created",
    4722: "account_enabled",
    4725: "account_disabled",
    4726: "account_deleted",
    4738: "account_changed",
    4740: "account_locked",
}

PRIVILEGED_LOGON_TYPES = {2, 10, 11}
SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
}
ADMINISTRATIVE_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "backup operators",
}


@dataclass(frozen=True)
class SecurityEvent:
    event_id: int
    timestamp: datetime
    computer: str
    subject_user: str
    target_user: str | None = None
    source_ip: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    logon_type: int | None = None
    privilege: str | None = None
    group_name: str | None = None
    message: str = ""

    @property
    def kind(self) -> str:
        return WINDOWS_EVENT_IDS.get(self.event_id, "other")


@dataclass(frozen=True)
class Alert:
    severity: str
    rule: str
    timestamp: datetime
    computer: str
    user: str
    evidence: str


def parse_timestamp(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_ip(value: str | None) -> None:
    if value is None:
        return
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if not re.fullmatch(pattern, value):
        raise ValueError(f"Invalid IPv4 address: {value}")
    octets = value.split(".")
    if any(int(octet) > 255 for octet in octets):
        raise ValueError(f"Invalid IPv4 address: {value}")


def parse_event(row: dict[str, str]) -> SecurityEvent:
    event_id = int(row["event_id"])
    if event_id < 1:
        raise ValueError("event_id must be positive")

    timestamp = parse_timestamp(row["timestamp"])
    validate_ip(row.get("source_ip") or None)

    process_id = int(row["process_id"]) if row.get("process_id") else None
    logon_type = int(row["logon_type"]) if row.get("logon_type") else None

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        computer=row["computer"].strip(),
        subject_user=row["subject_user"].strip(),
        target_user=(row.get("target_user") or "").strip() or None,
        source_ip=(row.get("source_ip") or "").strip() or None,
        process_name=(row.get("process_name") or "").strip().lower() or None,
        process_id=process_id,
        logon_type=logon_type,
        privilege=(row.get("privilege") or "").strip() or None,
        group_name=(row.get("group_name") or "").strip().lower() or None,
        message=(row.get("message") or "").strip(),
    )


def load_events(path: Path) -> list[SecurityEvent]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"event_id", "timestamp", "computer", "subject_user"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing CSV columns: {', '.join(sorted(missing))}")

        events = [parse_event(row) for row in reader]

    return sorted(events, key=lambda event: event.timestamp)


def sample_events() -> list[SecurityEvent]:
    base = datetime(2026, 10, 20, 5, 0, tzinfo=timezone.utc)

    return [
        SecurityEvent(
            4624, base, "WS-01", "SYSTEM", "alice",
            "10.10.1.20", logon_type=2,
        ),
        SecurityEvent(
            4688, base + timedelta(minutes=1), "WS-01", "alice",
            process_name="explorer.exe", process_id=2100,
        ),
        SecurityEvent(
            4688, base + timedelta(minutes=2), "WS-01", "alice",
            process_name="powershell.exe", process_id=2120,
            message="PowerShell started from an interactive session",
        ),
        SecurityEvent(
            4672, base + timedelta(minutes=2), "WS-01", "alice",
            privilege="SeDebugPrivilege",
        ),
        SecurityEvent(
            4625, base + timedelta(minutes=3), "WS-01", "bob",
            "administrator", "10.10.1.90", logon_type=10,
        ),
        SecurityEvent(
            4625, base + timedelta(minutes=4), "WS-01", "bob",
            "administrator", "10.10.1.90", logon_type=10,
        ),
        SecurityEvent(
            4625, base + timedelta(minutes=5), "WS-01", "bob",
            "administrator", "10.10.1.90", logon_type=10,
        ),
        SecurityEvent(
            4720, base + timedelta(minutes=8), "DC-01", "admin",
            "backupsvc",
            message="New local service account created",
        ),
        SecurityEvent(
            4722, base + timedelta(minutes=9), "DC-01", "admin",
            "backupsvc",
        ),
        SecurityEvent(
            4672, base + timedelta(minutes=10), "DC-01", "admin",
            privilege="SeBackupPrivilege",
        ),
        SecurityEvent(
            4688, base + timedelta(minutes=12), "DC-01", "backupsvc",
            process_name="cmd.exe", process_id=3300,
        ),
    ]


def detect_failed_logon_burst(
    events: Iterable[SecurityEvent],
    threshold: int = 3,
    window: timedelta = timedelta(minutes=5),
) -> list[Alert]:
    failed = [event for event in events if event.event_id == 4625]
    by_account: defaultdict[str, list[SecurityEvent]] = defaultdict(list)

    for event in failed:
        by_account[event.target_user or event.subject_user].append(event)

    alerts: list[Alert] = []

    for user, account_events in by_account.items():
        left = 0
        for right, current in enumerate(account_events):
            while current.timestamp - account_events[left].timestamp > window:
                left += 1

            count = right - left + 1
            if count >= threshold:
                first = account_events[left]
                alerts.append(
                    Alert(
                        "high",
                        "failed_logon_burst",
                        current.timestamp,
                        current.computer,
                        user,
                        f"{count} failed logons within {window}",
                    )
                )
                break

    return alerts


def detect_privileged_activity(events: Iterable[SecurityEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.event_id == 4672:
            privilege = event.privilege or "special privilege"
            severity = "high" if "debug" in privilege.lower() else "medium"
            alerts.append(
                Alert(
                    severity,
                    "special_privilege_assignment",
                    event.timestamp,
                    event.computer,
                    event.subject_user,
                    privilege,
                )
            )

        if event.event_id == 4688 and event.process_name in SUSPICIOUS_PROCESSES:
            alerts.append(
                Alert(
                    "medium",
                    "administrative_or_script_interpreter_process",
                    event.timestamp,
                    event.computer,
                    event.subject_user,
                    f"{event.process_name} PID={event.process_id}",
                )
            )

    return alerts


def detect_account_changes(events: Iterable[SecurityEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.event_id in {4720, 4722, 4725, 4726, 4738}:
            action = event.kind
            target = event.target_user or "unknown"
            severity = "high" if event.event_id in {4720, 4722} else "medium"

            alerts.append(
                Alert(
                    severity,
                    "account_activity",
                    event.timestamp,
                    event.computer,
                    event.subject_user,
                    f"{action}: target={target}",
                )
            )

    return alerts


def detect_privileged_interactive_logons(
    events: Iterable[SecurityEvent],
) -> list[Alert]:
    alerts = []

    for event in events:
        if event.event_id == 4624 and event.logon_type in PRIVILEGED_LOGON_TYPES:
            user = event.target_user or event.subject_user
            if user.lower() in {"administrator", "admin"}:
                alerts.append(
                    Alert(
                        "high",
                        "privileged_interactive_logon",
                        event.timestamp,
                        event.computer,
                        user,
                        f"logon_type={event.logon_type}, source={event.source_ip}",
                    )
                )

    return alerts


def aggregate(events: Iterable[SecurityEvent]) -> dict[str, object]:
    event_list = list(events)
    return {
        "event_count": len(event_list),
        "event_types": Counter(event.kind for event in event_list),
        "computers": Counter(event.computer for event in event_list),
        "users": Counter(
            event.target_user or event.subject_user for event in event_list
        ),
    }


def fingerprint_event(event: SecurityEvent) -> str:
    canonical = json.dumps(
        asdict(event),
        sort_keys=True,
        default=lambda value: value.isoformat()
        if isinstance(value, datetime)
        else value,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def run_monitor(events: list[SecurityEvent]) -> list[Alert]:
    alerts = []
    alerts.extend(detect_failed_logon_burst(events))
    alerts.extend(detect_privileged_activity(events))
    alerts.extend(detect_account_changes(events))
    alerts.extend(detect_privileged_interactive_logons(events))

    return sorted(
        alerts,
        key=lambda alert: (alert.timestamp, alert.severity, alert.rule),
    )


def print_report(events: list[SecurityEvent], alerts: list[Alert]) -> None:
    stats = aggregate(events)

    print("WINDOWS SECURITY MONITOR")
    print("========================")
    print(f"Events analyzed: {stats['event_count']}")

    print("\nEvent types:")
    for name, count in stats["event_types"].most_common():
        print(f"  {name}: {count}")

    print("\nAlerts:")
    if not alerts:
        print("  No detection rules triggered.")
    else:
        for alert in alerts:
            print(
                f"  [{alert.severity.upper()}] "
                f"{alert.timestamp.isoformat()} "
                f"{alert.computer} {alert.user} "
                f"{alert.rule}: {alert.evidence}"
            )

    print("\nEvent fingerprints:")
    for event in events[:5]:
        print(
            f"  {event.timestamp.isoformat()} "
            f"{event.event_id} "
            f"{fingerprint_event(event)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze normalized Windows Security event records."
    )
    parser.add_argument(
        "--csv",
        type=Path,
        help="CSV containing normalized Windows Security events.",
    )
    args = parser.parse_args()

    try:
        events = load_events(args.csv) if args.csv else sample_events()
        if not events:
            raise ValueError("No security events were supplied.")

        alerts = run_monitor(events)
        print_report(events, alerts)
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
