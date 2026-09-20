# File: src/port_inspector/models.py

from __future__ import annotations

# File: src/port_inspector/models.py

from dataclasses import asdict, dataclass
from typing import Any, Literal

ProtocolName = Literal["tcp", "udp"]


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A normalized representation of one locally observed network endpoint."""

    protocol: ProtocolName
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str = "UNKNOWN"
    pid: int | None = None
    process_name: str | None = None
    service: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible dictionary."""
        return asdict(self)

    @property
    def is_listening(self) -> bool:
        """Return whether this endpoint represents a TCP listening socket."""
        return self.protocol == "tcp" and self.state.upper() == "LISTEN"


def validate_port(port: int) -> int:
    """Validate a TCP/UDP port number."""
    if not isinstance(port, int) or isinstance(port, bool):
        raise TypeError("port must be an integer")
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return port


def normalize_protocol(protocol: str) -> ProtocolName:
    """Normalize and validate a protocol name."""
    value = protocol.strip().lower()
    if value not in {"tcp", "udp"}:
        raise ValueError("protocol must be 'tcp' or 'udp'")
    return value  # type: ignore[return-value]
