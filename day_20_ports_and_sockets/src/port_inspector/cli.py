# File: src/port_inspector/cli.py

# File: src/port_inspector/cli.py

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Sequence

from .inspector import filter_endpoints, inspect_endpoints


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect local TCP and UDP endpoints."
    )
    parser.add_argument(
        "--protocol",
        choices=("tcp", "udp"),
        help="show only one transport protocol",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="show only one local port",
    )
    parser.add_argument(
        "--listening",
        action="store_true",
        help="show only TCP listening endpoints",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable JSON",
    )
    parser.add_argument(
        "--no-process-details",
        action="store_true",
        help="use the standard-library fallback instead of process-aware inspection",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if args.port is not None and not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")

    endpoints = inspect_endpoints(prefer_process_details=not args.no_process_details)
    endpoints = filter_endpoints(
        endpoints,
        protocol=args.protocol,
        port=args.port,
        listening_only=args.listening,
    )

    if args.json:
        print(json.dumps([endpoint.to_dict() for endpoint in endpoints], indent=2))
        return 0

    headers = (
        "PROTO",
        "LOCAL",
        "REMOTE",
        "STATE",
        "PID",
        "PROCESS",
        "SERVICE",
    )
    print(" ".join(f"{header:<18}" for header in headers))

    for endpoint in endpoints:
        local = f"{endpoint.local_address}:{endpoint.local_port}"
        remote = (
            f"{endpoint.remote_address}:{endpoint.remote_port}"
            if endpoint.remote_address and endpoint.remote_port is not None
            else "-"
        )
        values = (
            endpoint.protocol,
            local,
            remote,
            endpoint.state,
            str(endpoint.pid) if endpoint.pid is not None else "-",
            endpoint.process_name or "-",
            endpoint.service or "-",
        )
        print(" ".join(f"{value:<18}" for value in values))

    print(f"\nEndpoints: {len(endpoints)}")
    return 0
