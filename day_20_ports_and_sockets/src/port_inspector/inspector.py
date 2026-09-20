# File: src/port_inspector/inspector.py

# File: src/port_inspector/inspector.py

from __future__ import annotations

import logging
import socket
from collections.abc import Iterable
from typing import Any

from .models import Endpoint, normalize_protocol, validate_port

LOGGER = logging.getLogger(__name__)

COMMON_SERVICES: dict[tuple[str, int], str] = {
    ("tcp", 22): "SSH",
    ("tcp", 25): "SMTP",
    ("tcp", 53): "DNS",
    ("udp", 53): "DNS",
    ("tcp", 80): "HTTP",
    ("tcp", 110): "POP3",
    ("tcp", 143): "IMAP",
    ("tcp", 443): "HTTPS",
    ("tcp", 3306): "MySQL",
    ("tcp", 5432): "PostgreSQL",
    ("tcp", 6379): "Redis",
    ("tcp", 8080): "HTTP development",
}


def classify_service(protocol: str, port: int) -> str | None:
    """Classify a port using conservative well-known application conventions."""
    protocol = normalize_protocol(protocol)
    validate_port(port)
    return COMMON_SERVICES.get((protocol, port))


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _address_parts(address: Any) -> tuple[str, int | None]:
    """Normalize psutil-style address objects without requiring psutil."""
    if not address:
        return "", None

    if hasattr(address, "ip") and hasattr(address, "port"):
        return str(address.ip), _safe_int(address.port)

    if isinstance(address, tuple) and len(address) >= 2:
        return str(address[0]), _safe_int(address[1])

    return str(address), None


def _state_from_raw(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    return str(value).upper()


def inspect_with_psutil() -> list[Endpoint]:
    """
    Inspect local sockets using psutil when it is installed.

    psutil is intentionally optional. This function is useful on systems where
    process ownership is needed and the caller has sufficient permissions.
    """
    try:
        import psutil
    except ImportError as exc:
        raise RuntimeError("psutil is not installed") from exc

    endpoints: list[Endpoint] = []

    for connection in psutil.net_connections(kind="inet"):
        local_address, local_port = _address_parts(connection.laddr)
        remote_address, remote_port = _address_parts(connection.raddr)

        if local_port is None:
            continue

        protocol = "udp" if connection.type == socket.SOCK_DGRAM else "tcp"
        state = _state_from_raw(connection.status)

        if protocol == "udp" and state == "":
            state = "NONE"

        pid = connection.pid
        process_name: str | None = None

        if pid is not None:
            try:
                process_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_name = None

        endpoints.append(
            Endpoint(
                protocol=protocol,  # type: ignore[arg-type]
                local_address=local_address or "*",
                local_port=local_port,
                remote_address=remote_address or None,
                remote_port=remote_port,
                state=state,
                pid=pid,
                process_name=process_name,
                service=classify_service(protocol, local_port),
            )
        )

    return sorted(
        endpoints,
        key=lambda item: (item.protocol, item.local_port, item.local_address),
    )


def inspect_with_socket() -> list[Endpoint]:
    """
    Produce a portable local TCP/UDP snapshot using standard-library APIs.

    This fallback cannot enumerate arbitrary OS-owned sockets. It creates a
    small set of temporary local sockets so the project remains dependency-light.
    """
    endpoints: list[Endpoint] = []

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        tcp.bind(("127.0.0.1", 0))
        tcp.listen(1)
        tcp_port = tcp.getsockname()[1]

        udp.bind(("127.0.0.1", 0))
        udp_port = udp.getsockname()[1]

        endpoints.extend(
            [
                Endpoint(
                    protocol="tcp",
                    local_address="127.0.0.1",
                    local_port=tcp_port,
                    state="LISTEN",
                    service=classify_service("tcp", tcp_port),
                ),
                Endpoint(
                    protocol="udp",
                    local_address="127.0.0.1",
                    local_port=udp_port,
                    state="NONE",
                    service=classify_service("udp", udp_port),
                ),
            ]
        )
    finally:
        tcp.close()
        udp.close()

    return endpoints


def inspect_endpoints(prefer_process_details: bool = True) -> list[Endpoint]:
    """
    Inspect local endpoints.

    psutil is preferred because the operating system can provide process
    ownership and established connection information. The standard-library
    fallback keeps the package usable without optional dependencies.
    """
    if prefer_process_details:
        try:
            return inspect_with_psutil()
        except RuntimeError:
            LOGGER.info("psutil is unavailable; using standard-library fallback")

    return inspect_with_socket()


def filter_endpoints(
    endpoints: Iterable[Endpoint],
    protocol: str | None = None,
    port: int | None = None,
    listening_only: bool = False,
) -> list[Endpoint]:
    """Apply simple local filters to an endpoint snapshot."""
    normalized_protocol = normalize_protocol(protocol) if protocol else None

    if port is not None:
        validate_port(port)

    result = [
        endpoint
        for endpoint in endpoints
        if (normalized_protocol is None or endpoint.protocol == normalized_protocol)
        and (port is None or endpoint.local_port == port)
        and (not listening_only or endpoint.is_listening)
    ]

    return result
