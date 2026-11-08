#!/usr/bin/env python3
"""
Secure Communications Laboratory
Topics:
- SSH remote access and host verification
- HTTPS and TLS certificate validation
- VPN tunnel policy and connection monitoring
- Secure file transfer using OpenSSH SFTP
- Communication security auditing

Requires Python 3.10+.
Uses Python standard-library modules and installed OpenSSH utilities.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("secure-communications")


class SecurityError(Exception):
    """Base exception for security-related failures."""


class ValidationError(SecurityError):
    pass


class ConnectionError(SecurityError):
    pass


class TransferError(SecurityError):
    pass


class Protocol(Enum):
    SSH = "SSH"
    HTTPS = "HTTPS"
    VPN = "VPN"
    SFTP = "SFTP"


class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"


@dataclass(frozen=True)
class SecurityPolicy:
    minimum_tls_version: str = "TLSv1.2"
    verify_certificates: bool = True
    verify_hostname: bool = True
    strict_ssh_host_checking: bool = True
    allow_weak_algorithms: bool = False
    maximum_file_size: int = 50 * 1024 * 1024

    def validate(self) -> None:
        if not self.verify_certificates:
            raise ValidationError("Certificate verification must remain enabled.")

        if not self.verify_hostname:
            raise ValidationError("Hostname verification must remain enabled.")

        if not self.strict_ssh_host_checking:
            raise ValidationError("Strict SSH host checking is required.")

        if self.allow_weak_algorithms:
            raise ValidationError("Weak cryptographic algorithms are prohibited.")

        if self.maximum_file_size <= 0:
            raise ValidationError("Maximum file size must be positive.")


@dataclass
class ConnectionRecord:
    identifier: str
    protocol: Protocol
    destination: str
    state: ConnectionState = ConnectionState.DISCONNECTED
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    details: dict = field(default_factory=dict)


@dataclass
class TransferRecord:
    source: str
    destination: str
    size: int
    sha256: str
    protocol: str
    timestamp: str
    success: bool


class SecurityAuditor:
    """Stores communication and transfer audit events."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, category: str, message: str, success: bool) -> None:
        self.events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": category,
            "message": message,
            "success": success,
        })

        if success:
            logger.info("%s: %s", category, message)
        else:
            logger.warning("%s: %s", category, message)

    def export(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)

        temporary = destination.with_suffix(destination.suffix + ".tmp")

        try:
            temporary.write_text(
                json.dumps(self.events, indent=2),
                encoding="utf-8",
            )
            temporary.replace(destination)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise


class TLSClient:
    """Performs HTTPS requests with certificate and hostname validation."""

    def __init__(
        self,
        policy: SecurityPolicy,
        timeout: int = 10,
    ) -> None:
        policy.validate()

        if timeout <= 0:
            raise ValidationError("Timeout must be positive.")

        self.timeout = timeout
        self.context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH
        )

        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def request(self, url: str) -> dict:
        parsed = urlparse(url)

        if parsed.scheme != "https" or not parsed.hostname:
            raise ValidationError("A valid HTTPS URL is required.")

        if parsed.username or parsed.password:
            raise ValidationError("Credentials in URLs are prohibited.")

        request = urllib.request.Request(
            url,
            headers={"User-Agent": "SecureCommunicationsLab/1.0"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(
                request,
                context=self.context,
                timeout=self.timeout,
            ) as response:
                body = response.read(1024 * 1024 + 1)

                if len(body) > 1024 * 1024:
                    raise SecurityError("Response exceeds the 1 MB limit.")

                return {
                    "url": response.url,
                    "status": response.status,
                    "content_type": response.headers.get("Content-Type"),
                    "body_size": len(body),
                    "tls_verified": True,
                }

        except (OSError, ssl.SSLError) as exc:
            raise ConnectionError(
                f"HTTPS connection failed: {exc}"
            ) from exc


class SSHManager:
    """Uses the system OpenSSH client without accepting unknown host keys."""

    def __init__(
        self,
        policy: SecurityPolicy,
        known_hosts: Path,
        identity_file: Optional[Path] = None,
    ) -> None:
        policy.validate()

        self.known_hosts = known_hosts.expanduser().resolve()
        self.identity_file = (
            identity_file.expanduser().resolve()
            if identity_file else None
        )

        if not self.known_hosts.is_file():
            raise ValidationError(
                "A provisioned SSH known_hosts file is required."
            )

        if self.identity_file and not self.identity_file.is_file():
            raise ValidationError("SSH identity file does not exist.")

        if shutil.which("ssh") is None:
            raise ValidationError("OpenSSH client is not installed.")

    @staticmethod
    def validate_host(host: str) -> None:
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}",
            host,
        ):
            raise ValidationError("Invalid SSH hostname.")

    @staticmethod
    def validate_username(username: str) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", username):
            raise ValidationError("Invalid SSH username.")

    def connect(
        self,
        username: str,
        host: str,
        command: str = "id",
    ) -> subprocess.CompletedProcess:
        self.validate_username(username)
        self.validate_host(host)

        if not command or "\x00" in command:
            raise ValidationError("Invalid remote command.")

        args = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ForwardAgent=no",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
        ]

        if self.identity_file:
            args.extend(["-i", str(self.identity_file)])

        args.extend([
            f"{username}@{host}",
            command,
        ])

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

            if result.returncode != 0:
                raise ConnectionError(
                    f"SSH failed: {result.stderr.strip()}"
                )

            return result

        except subprocess.TimeoutExpired as exc:
            raise ConnectionError("SSH connection timed out.") from exc


class SecureFileTransfer:
    """Transfers files through OpenSSH SFTP with strict host verification."""

    def __init__(
        self,
        policy: SecurityPolicy,
        known_hosts: Path,
        identity_file: Optional[Path] = None,
    ) -> None:
        policy.validate()

        self.policy = policy
        self.known_hosts = known_hosts.expanduser().resolve()
        self.identity_file = (
            identity_file.expanduser().resolve()
            if identity_file else None
        )

        if not self.known_hosts.is_file():
            raise ValidationError("SFTP known_hosts file is missing.")

        if shutil.which("sftp") is None:
            raise ValidationError("OpenSSH SFTP client is not installed.")

    def upload(
        self,
        local_file: Path,
        username: str,
        host: str,
        remote_path: str,
    ) -> TransferRecord:
        local_file = local_file.expanduser().resolve()

        if not local_file.is_file() or local_file.is_symlink():
            raise ValidationError("A regular local file is required.")

        if not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_.-]{0,31}",
            username,
        ):
            raise ValidationError("Invalid username.")

        SSHManager.validate_host(host)

        if (
            not remote_path.startswith("/")
            or "\n" in remote_path
            or "\r" in remote_path
            or "\x00" in remote_path
            or any(part in {".", ".."} for part in remote_path.split("/"))
        ):
            raise ValidationError("Invalid absolute remote path.")

        size = local_file.stat().st_size

        if size > self.policy.maximum_file_size:
            raise TransferError("File exceeds configured size limit.")

        digest = hashlib.sha256()

        with local_file.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)

        remote_directory = remote_path.rsplit("/", 1)[0]
        remote_name = remote_path.rsplit("/", 1)[1]

        if not remote_name:
            raise ValidationError("Remote filename is required.")

        with tempfile.TemporaryDirectory() as directory:
            batch_file = Path(directory) / "sftp.batch"

            # OpenSSH batch commands do not support arbitrary shell commands.
            # Reject characters that could alter batch command structure.
            if re.search(r"[\s\"'\\]", remote_path):
                raise ValidationError(
                    "Remote paths containing whitespace or quotes "
                    "are not supported by this batch workflow."
                )

            batch_file.write_text(
                f'put "{local_file}" "{remote_path}"\n'
                f'ls "{remote_path}"\n'
                'bye\n',
                encoding="utf-8",
            )

            os.chmod(batch_file, 0o600)

            args = [
                "sftp",
                "-b", str(batch_file),
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "IdentitiesOnly=yes",
                "-o", "ConnectTimeout=10",
                "-o", f"UserKnownHostsFile={self.known_hosts}",
            ]

            if self.identity_file:
                if not self.identity_file.is_file():
                    raise ValidationError("SSH identity file is missing.")
                args.extend(["-i", str(self.identity_file)])

            args.append(f"{username}@{host}")

            try:
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )

                if result.returncode != 0:
                    raise TransferError(
                        f"SFTP transfer failed: {result.stderr.strip()}"
                    )

            except subprocess.TimeoutExpired as exc:
                raise TransferError("SFTP transfer timed out.") from exc

        return TransferRecord(
            source=str(local_file),
            destination=f"{username}@{host}:{remote_path}",
            size=size,
            sha256=digest.hexdigest(),
            protocol="SFTP over SSH",
            timestamp=datetime.now(timezone.utc).isoformat(),
            success=True,
        )


class VPNProfile:
    """Validates VPN configuration metadata without changing system routes."""

    def __init__(
        self,
        interface: str,
        endpoint: str,
        allowed_networks: list[str],
        encryption: str = "WireGuard",
    ) -> None:
        import ipaddress

        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            raise ValidationError("Invalid VPN interface name.")

        if not re.fullmatch(
            r"[A-Za-z0-9.-]+:[0-9]{1,5}",
            endpoint,
        ):
            raise ValidationError("Invalid VPN endpoint.")

        port = int(endpoint.rsplit(":", 1)[1])

        if not 1 <= port <= 65535:
            raise ValidationError("Invalid VPN endpoint port.")

        if encryption not in {"WireGuard", "IPsec"}:
            raise ValidationError("Unsupported VPN protocol.")

        if not allowed_networks:
            raise ValidationError("At least one allowed network is required.")

        networks = []

        for network in allowed_networks:
            try:
                networks.append(
                    str(ipaddress.ip_network(network, strict=True))
                )
            except ValueError as exc:
                raise ValidationError(
                    f"Invalid VPN network: {network}"
                ) from exc

        self.interface = interface
        self.endpoint = endpoint
        self.allowed_networks = networks
        self.encryption = encryption

    def summary(self) -> dict:
        return {
            "interface": self.interface,
            "endpoint": self.endpoint,
            "allowed_networks": self.allowed_networks,
            "protocol": self.encryption,
            "configuration_valid": True,
        }


class CommunicationRegistry:
    """Maintains communication lifecycle states."""

    def __init__(self, auditor: SecurityAuditor) -> None:
        self.records: dict[str, ConnectionRecord] = {}
        self.auditor = auditor

    def register(
        self,
        identifier: str,
        protocol: Protocol,
        destination: str,
    ) -> ConnectionRecord:
        if not identifier or identifier in self.records:
            raise ValidationError("Invalid or duplicate connection ID.")

        record = ConnectionRecord(
            identifier=identifier,
            protocol=protocol,
            destination=destination,
        )

        self.records[identifier] = record
        return record

    def transition(
        self,
        identifier: str,
        state: ConnectionState,
    ) -> None:
        record = self.records.get(identifier)

        if record is None:
            raise ValidationError("Unknown connection.")

        allowed = {
            ConnectionState.DISCONNECTED: {
                ConnectionState.CONNECTING,
            },
            ConnectionState.CONNECTING: {
                ConnectionState.CONNECTED,
                ConnectionState.FAILED,
            },
            ConnectionState.CONNECTED: {
                ConnectionState.DISCONNECTED,
                ConnectionState.FAILED,
            },
            ConnectionState.FAILED: {
                ConnectionState.DISCONNECTED,
            },
        }

        if state not in allowed[record.state]:
            raise SecurityError(
                f"Invalid transition: {record.state.value} -> {state.value}"
            )

        record.state = state

        self.auditor.record(
            record.protocol.value,
            f"{identifier}: {state.value}",
            state != ConnectionState.FAILED,
        )


def run_demonstration() -> None:
    policy = SecurityPolicy()
    policy.validate()

    auditor = SecurityAuditor()
    registry = CommunicationRegistry(auditor)

    print("\n=== SECURE COMMUNICATIONS LAB ===")

    print("\n1. Security policy")
    print(json.dumps(asdict(policy), indent=2))

    print("\n2. HTTPS and TLS")
    registry.register(
        "HTTPS-001",
        Protocol.HTTPS,
        "https://example.com",
    )

    registry.transition("HTTPS-001", ConnectionState.CONNECTING)

    try:
        response = TLSClient(policy).request("https://example.com")

        registry.transition("HTTPS-001", ConnectionState.CONNECTED)
        print(json.dumps(response, indent=2))

        registry.transition("HTTPS-001", ConnectionState.DISCONNECTED)

    except (SecurityError, OSError) as exc:
        registry.transition("HTTPS-001", ConnectionState.FAILED)
        print(f"HTTPS validation result: {exc}")

    print("\n3. SSH configuration")
    known_hosts = Path.home() / ".ssh" / "known_hosts"

    if known_hosts.is_file() and shutil.which("ssh"):
        print("OpenSSH available.")
        print("Known-hosts database exists.")
        print("Unknown host keys will be rejected.")
        print("No remote command is executed automatically.")
    else:
        print("SSH prerequisites are not configured.")

    print("\n4. VPN configuration")
    vpn = VPNProfile(
        interface="wg0",
        endpoint="vpn.example.com:51820",
        allowed_networks=[
            "10.20.0.0/16",
            "192.168.50.0/24",
        ],
    )

    print(json.dumps(vpn.summary(), indent=2))

    print("\n5. Secure file transfer")
    with tempfile.TemporaryDirectory() as directory:
        sample = Path(directory) / "confidential.txt"
        sample.write_text(
            "Confidential enterprise communication record.",
            encoding="utf-8",
        )

        transfer = TransferRecord(
            source=str(sample),
            destination="sftp.example.com:/incoming/confidential.txt",
            size=sample.stat().st_size,
            sha256=hashlib.sha256(sample.read_bytes()).hexdigest(),
            protocol="SFTP over SSH",
            timestamp=datetime.now(timezone.utc).isoformat(),
            success=True,
        )

        print(json.dumps(asdict(transfer), indent=2))
        print("This record demonstrates local integrity calculation.")
        print("No remote transfer was performed.")

    print("\n6. Failure validation")

    try:
        SecurityPolicy(
            verify_certificates=False
        ).validate()
    except ValidationError as exc:
        print(f"Blocked insecure configuration: {exc}")

    try:
        VPNProfile(
            interface="wg0",
            endpoint="vpn.example.com:51820",
            allowed_networks=["10.20.0.999/24"],
        )
    except ValidationError as exc:
        print(f"Blocked invalid VPN network: {exc}")

    print("\n7. Audit events")
    print(json.dumps(auditor.events, indent=2))

    print("\nSecure communications demonstration completed.")


def run_tests() -> None:
    policy = SecurityPolicy()
    policy.validate()

    assert policy.verify_certificates
    assert policy.strict_ssh_host_checking

    vpn = VPNProfile(
        "wg0",
        "vpn.example.com:51820",
        ["10.0.0.0/8"],
    )

    assert vpn.summary()["configuration_valid"]

    auditor = SecurityAuditor()
    registry = CommunicationRegistry(auditor)

    registry.register("TEST-001", Protocol.SSH, "server.example.com")
    registry.transition("TEST-001", ConnectionState.CONNECTING)
    registry.transition("TEST-001", ConnectionState.CONNECTED)

    try:
        registry.transition("TEST-001", ConnectionState.CONNECTING)
        raise AssertionError("Invalid transition was accepted.")
    except SecurityError:
        pass

    assert len(auditor.events) == 2

    print("All security policy and lifecycle tests passed.")


if __name__ == "__main__":
    run_tests()
    run_demonstration()
