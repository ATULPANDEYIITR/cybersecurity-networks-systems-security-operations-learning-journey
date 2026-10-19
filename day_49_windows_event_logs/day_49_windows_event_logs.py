"""
Windows Event Logs: Security, System, Application, PowerShell, and Authentication

A self-contained learning and operational script for Windows event-log analysis.
It uses only the Python standard library. On Windows, it can query live logs
through wevtutil.exe; elsewhere it analyzes supplied XML-shaped event records.

The implementation deliberately separates:
- Security events: auditing, logons, privilege-related activity
- System events: services, drivers, boot and operating-system events
- Application events: application crashes and application-generated failures
- PowerShell events: PowerShell execution and operational telemetry
- Authentication events: successful and failed authentication activity
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional


WINDOWS_EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": WINDOWS_EVENT_NAMESPACE}

LOGS = ("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational")

AUTHENTICATION_EVENT_IDS = {
    4624: "successful_logon",
    4625: "failed_logon",
    4634: "logoff",
    4647: "user_initiated_logoff",
    4672: "special_privileges_assigned",
    4768: "kerberos_tgt_requested",
    4769: "kerberos_service_ticket_requested",
    4771: "kerberos_pre_authentication_failed",
    4776: "ntlm_authentication",
}

POWERSHELL_EVENT_IDS = {
    400: "engine_started",
    403: "engine_stopped",
    600: "provider_started",
    4103: "module_logging",
    4104: "script_block_logging",
    4105: "command_started",
    4106: "command_stopped",
}

SUSPICIOUS_EVENT_IDS = {
    1102: "audit_log_cleared",
    4720: "user_account_created",
    4728: "member_added_to_security_enabled_global_group",
    4732: "member_added_to_security_enabled_local_group",
    4756: "member_added_to_security_enabled_universal_group",
    7045: "service_installed",
}


@dataclass
class EventRecord:
    record_id: int
    log_name: str
    provider: str
    event_id: int
    level: str
    timestamp: dt.datetime
    computer: str
    message: str
    user: Optional[str] = None
    ip_address: Optional[str] = None
    keywords: list[str] = field(default_factory=list)

    @property
    def event_name(self) -> str:
        if self.event_id in AUTHENTICATION_EVENT_IDS:
            return AUTHENTICATION_EVENT_IDS[self.event_id]
        if self.event_id in POWERSHELL_EVENT_IDS:
            return POWERSHELL_EVENT_IDS[self.event_id]
        if self.event_id in SUSPICIOUS_EVENT_IDS:
            return SUSPICIOUS_EVENT_IDS[self.event_id]
        return f"event_{self.event_id}"

    @property
    def is_authentication(self) -> bool:
        return self.event_id in AUTHENTICATION_EVENT_IDS

    @property
    def is_suspicious(self) -> bool:
        return self.event_id in SUSPICIOUS_EVENT_IDS


def parse_windows_timestamp(value: str) -> dt.datetime:
    """Convert Event XML's ISO timestamp to an aware datetime."""
    normalized = value.replace("Z", "+00:00")
    return dt.datetime.fromisoformat(normalized)


def event_from_xml(xml_text: str) -> EventRecord:
    """Parse a single Windows Event XML document."""
    root = ET.fromstring(xml_text)

    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("Event XML does not contain a System element")

    event_id_node = system.find("e:EventID", NS)
    time_node = system.find("e:TimeCreated", NS)
    record_node = system.find("e:EventRecordID", NS)

    if event_id_node is None or time_node is None:
        raise ValueError("Event XML is missing EventID or TimeCreated")

    provider_node = system.find("e:Provider", NS)
    computer_node = system.find("e:Computer", NS)
    level_node = system.find("e:Level", NS)

    provider = (
        provider_node.attrib.get("Name", "Unknown")
        if provider_node is not None
        else "Unknown"
    )
    timestamp = parse_windows_timestamp(
        time_node.attrib.get("SystemTime", dt.datetime.now(dt.timezone.utc).isoformat())
    )

    event_data = root.find("e:EventData", NS)
    fields: dict[str, str] = {}
    if event_data is not None:
        for item in event_data.findall("e:Data", NS):
            name = item.attrib.get("Name")
            if name:
                fields[name] = item.text or ""

    user = fields.get("TargetUserName") or fields.get("SubjectUserName")
    ip_address = fields.get("IpAddress") or fields.get("ClientAddress")

    rendered_fields = " ".join(
        f"{key}={value}" for key, value in fields.items() if value
    )

    return EventRecord(
        record_id=int(record_node.text) if record_node is not None and record_node.text else 0,
        log_name="Unknown",
        provider=provider,
        event_id=int(event_id_node.text or 0),
        level=level_node.text if level_node is not None and level_node.text else "Unknown",
        timestamp=timestamp,
        computer=computer_node.text if computer_node is not None and computer_node.text else "Unknown",
        message=rendered_fields,
        user=user,
        ip_address=ip_address,
    )


def run_wevtutil(
    log_name: str,
    *,
    max_events: int = 50,
    query: Optional[str] = None,
) -> list[EventRecord]:
    """
    Retrieve recent events using Windows' built-in wevtutil utility.

    XPath is used by the operating system rather than filtering the full
    result set in Python, which is important when a Security log is large.
    """
    if sys.platform != "win32":
        raise RuntimeError("Live Windows Event Log access requires Windows.")

    command = [
        "wevtutil",
        "qe",
        log_name,
        "/f:xml",
        f"/c:{max_events}",
        "/rd:true",
    ]
    if query:
        command.append(f"/q:{query}")

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "wevtutil failed")

    records: list[EventRecord] = []

    # wevtutil returns adjacent XML documents without a convenient JSON
    # boundary. Wrapping them in a synthetic Events element makes the
    # standard XML parser capable of processing the complete response.
    response = f"<Events>{completed.stdout}</Events>"
    try:
        root = ET.fromstring(response)
    except ET.ParseError as exc:
        raise RuntimeError(f"Could not parse wevtutil XML: {exc}") from exc

    for event_node in root.findall("e:Event", NS):
        record = event_from_xml(ET.tostring(event_node, encoding="unicode"))
        record.log_name = log_name
        records.append(record)

    return records


def sample_events() -> list[EventRecord]:
    """Provide deterministic data so the script remains executable without Windows."""
    base = dt.datetime(2026, 10, 19, 5, 0, tzinfo=dt.timezone.utc)
    return [
        EventRecord(
            1001, "Application", "Windows Error Reporting", 1001, "2",
            base, "WS-101", "Faulting application: inventory.exe"
        ),
        EventRecord(
            22001, "System", "Service Control Manager", 7045, "4",
            base + dt.timedelta(minutes=2), "WS-101",
            "ServiceName=RemoteSupport Agent ImagePath=C:\\ProgramData\\support.exe",
            user="SYSTEM",
        ),
        EventRecord(
            22002, "Security", "Microsoft-Windows-Security-Auditing", 4624, "0",
            base + dt.timedelta(minutes=5), "WS-101",
            "TargetUserName=alice LogonType=10 AuthenticationPackage=Negotiate",
            user="alice", ip_address="10.10.20.50",
        ),
        EventRecord(
            22003, "Security", "Microsoft-Windows-Security-Auditing", 4625, "0",
            base + dt.timedelta(minutes=6), "WS-101",
            "TargetUserName=administrator LogonType=3 Status=0xC000006D",
            user="administrator", ip_address="10.10.20.88",
        ),
        EventRecord(
            22004, "Security", "Microsoft-Windows-Security-Auditing", 4625, "0",
            base + dt.timedelta(minutes=6, seconds=20), "WS-101",
            "TargetUserName=administrator LogonType=3 Status=0xC000006D",
            user="administrator", ip_address="10.10.20.88",
        ),
        EventRecord(
            22005, "Security", "Microsoft-Windows-Security-Auditing", 1102, "0",
            base + dt.timedelta(minutes=9), "WS-101",
            "SubjectUserName=administrator Audit log was cleared",
            user="administrator",
        ),
        EventRecord(
            30001, "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell", 4104, "3",
            base + dt.timedelta(minutes=12), "WS-101",
            "ScriptBlockText=Get-Process; Get-Service",
            user="alice",
        ),
    ]


def summarize_by_log(records: Iterable[EventRecord]) -> dict[str, int]:
    return dict(Counter(record.log_name for record in records))


def summarize_event_ids(records: Iterable[EventRecord]) -> Counter[int]:
    return Counter(record.event_id for record in records)


def detect_failed_authentication_bursts(
    records: Iterable[EventRecord],
    *,
    threshold: int = 3,
    window_seconds: int = 300,
) -> list[dict[str, object]]:
    """
    Detect repeated 4625 failures by account and source address.

    This is a deliberately simple detection rule. Production detection should
    account for NAT, service accounts, scheduled jobs, distributed attacks,
    and domain-controller telemetry.
    """
    failures = [
        event for event in records
        if event.event_id == 4625 and event.ip_address
    ]

    grouped: dict[tuple[str, str], list[EventRecord]] = defaultdict(list)
    for event in failures:
        grouped[(event.user or "unknown", event.ip_address or "unknown")].append(event)

    findings = []
    for (user, ip), events in grouped.items():
        events.sort(key=lambda event: event.timestamp)
        for index, start in enumerate(events):
            end_index = index
            while end_index < len(events):
                delta = events[end_index].timestamp - start.timestamp
                if delta.total_seconds() > window_seconds:
                    break
                end_index += 1

            count = end_index - index
            if count >= threshold:
                findings.append({
                    "user": user,
                    "source_ip": ip,
                    "failed_attempts": count,
                    "window_seconds": window_seconds,
                    "first_seen": start.timestamp.isoformat(),
                    "last_seen": events[end_index - 1].timestamp.isoformat(),
                })
                break

    return findings


def correlate_authentication(records: Iterable[EventRecord]) -> list[dict[str, object]]:
    """Correlate successful and failed authentication activity by user."""
    result: dict[str, dict[str, int]] = defaultdict(
        lambda: {"successful": 0, "failed": 0, "privileged": 0}
    )

    for event in records:
        if event.event_id == 4624:
            result[event.user or "unknown"]["successful"] += 1
        elif event.event_id == 4625:
            result[event.user or "unknown"]["failed"] += 1
        elif event.event_id == 4672:
            result[event.user or "unknown"]["privileged"] += 1

    return [
        {"user": user, **counts}
        for user, counts in sorted(result.items())
    ]


def analyze_powershell(records: Iterable[EventRecord]) -> dict[str, object]:
    """Separate PowerShell engine activity from script-block telemetry."""
    powershell = [
        event for event in records
        if event.log_name.lower().endswith("powershell/operational")
    ]
    return {
        "events": len(powershell),
        "event_ids": dict(Counter(event.event_id for event in powershell)),
        "script_block_events": sum(event.event_id == 4104 for event in powershell),
        "users": sorted({event.user for event in powershell if event.user}),
    }


def validate_event(record: EventRecord) -> list[str]:
    """Return data-quality problems without silently modifying evidence."""
    errors = []

    if record.event_id < 0:
        errors.append("event_id cannot be negative")
    if not record.log_name:
        errors.append("log_name is empty")
    if not record.provider:
        errors.append("provider is empty")
    if record.timestamp.tzinfo is None:
        errors.append("timestamp must be timezone-aware")
    if record.event_id in {4624, 4625} and not record.user:
        errors.append("authentication event has no user")
    if record.event_id == 4625 and not record.ip_address:
        errors.append("failed authentication has no source address")

    return errors


def export_json(records: Iterable[EventRecord], path: Path) -> None:
    """Export normalized records without altering the original event fields."""
    payload = []
    for record in records:
        item = asdict(record)
        item["timestamp"] = record.timestamp.isoformat()
        item["event_name"] = record.event_name
        payload.append(item)

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def print_report(records: list[EventRecord]) -> None:
    print("\nWindows Event Log Analysis")
    print("=" * 72)

    print("\nLog distribution")
    for log_name, count in summarize_by_log(records).items():
        print(f"  {log_name}: {count}")

    print("\nEvent IDs")
    for event_id, count in summarize_event_ids(records).most_common():
        print(f"  {event_id}: {count}")

    print("\nAuthentication correlation")
    for row in correlate_authentication(records):
        print(
            f"  {row['user']}: successful={row['successful']} "
            f"failed={row['failed']} privileged={row['privileged']}"
        )

    print("\nPowerShell telemetry")
    print(json.dumps(analyze_powershell(records), indent=2))

    print("\nSecurity findings")
    for event in records:
        if event.is_suspicious:
            print(
                f"  [{event.timestamp.isoformat()}] "
                f"{event.log_name} {event.event_id} {event.event_name}: "
                f"{event.message}"
            )

    bursts = detect_failed_authentication_bursts(records, threshold=2)
    print("\nAuthentication burst detection")
    if bursts:
        for finding in bursts:
            print(" ", json.dumps(finding))
    else:
        print("  No configured authentication burst detected.")

    print("\nValidation")
    invalid = 0
    for event in records:
        errors = validate_event(event)
        if errors:
            invalid += 1
            print(f"  Record {event.record_id}: {', '.join(errors)}")
    print(f"  Records with validation errors: {invalid}")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Windows Security, System, Application and PowerShell events."
    )
    parser.add_argument(
        "--log",
        action="append",
        choices=LOGS,
        help="Live Windows log to query. May be specified more than once.",
    )
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument(
        "--xml-file",
        type=Path,
        help="Parse one or more Event XML documents from a file.",
    )
    return parser


def load_xml_file(path: Path) -> list[EventRecord]:
    text = path.read_text(encoding="utf-8")
    root = ET.fromstring(f"<Events>{text}</Events>")
    records = []

    for event_node in root.findall("e:Event", NS):
        records.append(
            event_from_xml(ET.tostring(event_node, encoding="unicode"))
        )

    return records


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        if args.xml_file:
            records = load_xml_file(args.xml_file)
            for record in records:
                if record.log_name == "Unknown":
                    record.log_name = "Imported"

        elif args.log:
            records = []
            for log_name in args.log:
                records.extend(run_wevtutil(log_name, max_events=args.count))

        elif sys.platform == "win32":
            records = []
            for log_name in LOGS:
                try:
                    records.extend(run_wevtutil(log_name, max_events=args.count))
                except RuntimeError as exc:
                    print(f"Warning: could not read {log_name}: {exc}", file=sys.stderr)

            if not records:
                records = sample_events()
        else:
            records = sample_events()

        print_report(records)

        if args.json_out:
            export_json(records, args.json_out)
            print(f"\nExported normalized events to {args.json_out}")

        return 0

    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
