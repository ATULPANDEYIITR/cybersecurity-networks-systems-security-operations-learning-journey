#!/usr/bin/env python3
"""
TLS Deep Dive: Handshake, Cipher Suites, Certificates, and Session Keys.

Uses Python's standard library and OpenSSL command-line utility.
Demonstrates TLS configuration inspection, certificate validation,
TLS connections, session reuse, and security policy evaluation.

Run:
    python tls_deep_dive.py
    python tls_deep_dive.py --host www.example.com --port 443
    python tls_deep_dive.py --host www.example.com --port 443 --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import socket
import ssl
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger("tls_deep_dive")


class TLSVersion(str, Enum):
    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"


class HandshakeState(str, Enum):
    CREATED = "created"
    CONNECTING = "connecting"
    ESTABLISHED = "established"
    FAILED = "failed"
    CLOSED = "closed"


class TLSValidationError(Exception):
    pass


@dataclass(frozen=True)
class TLSConfig:
    minimum_version: TLSVersion = TLSVersion.TLS_1_2
    maximum_version: TLSVersion = TLSVersion.TLS_1_3
    verify_certificates: bool = True
    check_hostname: bool = True
    timeout: float = 8.0

    def validate(self) -> None:
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive.")

        if (
            self.minimum_version == TLSVersion.TLS_1_3
            and self.maximum_version == TLSVersion.TLS_1_2
        ):
            raise ValueError("Minimum TLS version exceeds maximum.")


@dataclass
class HandshakeReport:
    host: str
    port: int
    state: str
    tls_version: Optional[str] = None
    cipher_name: Optional[str] = None
    cipher_protocol: Optional[str] = None
    cipher_bits: Optional[int] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[str] = None
    certificate_sha256: Optional[str] = None
    session_reused: bool = False
    elapsed_ms: Optional[float] = None
    error: Optional[str] = None


class TLSPolicy:
    """Evaluates negotiated TLS parameters against local policy."""

    APPROVED_VERSIONS = {
        "TLSv1.2",
        "TLSv1.3"
    }

    TLS13_CIPHERS = {
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
    }

    TLS12_CIPHERS = {
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-CHACHA20-POLY1305"
    }

    @classmethod
    def evaluate(cls, version: str, cipher: str) -> list[str]:
        violations = []

        if version not in cls.APPROVED_VERSIONS:
            violations.append("Unsupported TLS protocol version.")

        if version == "TLSv1.3" and cipher not in cls.TLS13_CIPHERS:
            violations.append("Cipher is outside the TLS 1.3 allowlist.")

        if version == "TLSv1.2" and cipher not in cls.TLS12_CIPHERS:
            violations.append("Cipher is outside the TLS 1.2 allowlist.")

        return violations


class TLSInspector:
    def __init__(self, config: TLSConfig):
        config.validate()
        self.config = config
        self.context = self._create_context()

    def _create_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        context.minimum_version = (
            ssl.TLSVersion.TLSv1_2
            if self.config.minimum_version == TLSVersion.TLS_1_2
            else ssl.TLSVersion.TLSv1_3
        )

        context.maximum_version = (
            ssl.TLSVersion.TLSv1_2
            if self.config.maximum_version == TLSVersion.TLS_1_2
            else ssl.TLSVersion.TLSv1_3
        )

        context.verify_mode = (
            ssl.CERT_REQUIRED
            if self.config.verify_certificates
            else ssl.CERT_NONE
        )

        context.check_hostname = (
            self.config.check_hostname
            and self.config.verify_certificates
        )

        if self.config.verify_certificates:
            context.load_default_certs()

        context.options |= ssl.OP_NO_COMPRESSION

        return context

    @staticmethod
    def _certificate_fingerprint(
        certificate_der: bytes
    ) -> str:
        return hashlib.sha256(certificate_der).hexdigest()

    @staticmethod
    def _certificate_field(
        certificate: dict,
        field: str
    ) -> Optional[str]:
        entries = certificate.get(field, ())

        if not entries:
            return None

        return ", ".join(
            f"{key}={value}"
            for group in entries
            for key, value in group
        )

    def inspect(self, host: str, port: int = 443) -> HandshakeReport:
        if not host or any(char.isspace() for char in host):
            raise ValueError("A valid hostname is required.")

        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

        report = HandshakeReport(
            host=host,
            port=port,
            state=HandshakeState.CREATED.value
        )

        started = datetime.now(timezone.utc)

        try:
            report.state = HandshakeState.CONNECTING.value

            with socket.create_connection(
                (host, port),
                timeout=self.config.timeout
            ) as raw_socket:

                with self.context.wrap_socket(
                    raw_socket,
                    server_hostname=host
                ) as tls_socket:

                    report.state = HandshakeState.ESTABLISHED.value
                    report.tls_version = tls_socket.version()

                    cipher = tls_socket.cipher()

                    if cipher:
                        report.cipher_name = cipher[0]
                        report.cipher_protocol = cipher[1]
                        report.cipher_bits = cipher[2]

                    report.session_reused = tls_socket.session_reused

                    certificate = tls_socket.getpeercert()
                    certificate_der = tls_socket.getpeercert(
                        binary_form=True
                    )

                    if certificate:
                        report.certificate_subject = (
                            self._certificate_field(
                                certificate, "subject"
                            )
                        )

                        report.certificate_issuer = (
                            self._certificate_field(
                                certificate, "issuer"
                            )
                        )

                        report.certificate_expiry = (
                            certificate.get("notAfter")
                        )

                    if certificate_der:
                        report.certificate_sha256 = (
                            self._certificate_fingerprint(
                                certificate_der
                            )
                        )

                    violations = TLSPolicy.evaluate(
                        report.tls_version or "",
                        report.cipher_name or ""
                    )

                    if violations:
                        logger.warning(
                            "TLS policy violations: %s",
                            "; ".join(violations)
                        )

        except (
            ssl.SSLCertVerificationError,
            ssl.SSLError,
            socket.timeout,
            socket.gaierror,
            ConnectionError,
            OSError
        ) as exc:
            report.state = HandshakeState.FAILED.value
            report.error = f"{type(exc).__name__}: {exc}"

        finally:
            elapsed = (
                datetime.now(timezone.utc) - started
            ).total_seconds() * 1000

            report.elapsed_ms = round(elapsed, 2)

        return report


def display_supported_ciphers() -> None:
    context = ssl.create_default_context()

    print("\nSupported TLS Cipher Suites")
    print("-" * 75)

    for cipher in context.get_ciphers():
        print(
            f"{cipher['protocol']:10} "
            f"{cipher['name']:48} "
            f"{cipher['strength_bits']:4} bits"
        )


def inspect_certificate_with_openssl(
    host: str,
    port: int
) -> Optional[str]:
    """Optional independent certificate inspection."""

    command = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-verify_return_error",
        "-brief"
    ]

    try:
        result = subprocess.run(
            command,
            input="",
            capture_output=True,
            text=True,
            timeout=12,
            check=False
        )

        return result.stdout + result.stderr

    except FileNotFoundError:
        logger.info("OpenSSL executable is not installed.")
    except subprocess.TimeoutExpired:
        logger.warning("OpenSSL inspection timed out.")
    except OSError as exc:
        logger.warning("OpenSSL inspection failed: %s", exc)

    return None


def demonstrate_session_concepts() -> None:
    print("\nTLS Session Concepts")
    print("-" * 75)

    concepts = {
        "TLS handshake": (
            "Negotiates protocol parameters, authenticates the server "
            "and establishes shared traffic secrets."
        ),
        "Certificate": (
            "Binds a public key to an identity through a CA signature."
        ),
        "Cipher suite": (
            "Defines cryptographic algorithms used by the TLS connection."
        ),
        "Session key": (
            "Derived traffic secrets protect application data."
        ),
        "Session resumption": (
            "Allows a later connection to reuse previously established "
            "authentication and key-establishment state under protocol rules."
        )
    }

    for name, description in concepts.items():
        print(f"{name}: {description}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TLS handshake and certificate inspection."
    )

    parser.add_argument(
        "--host",
        default="example.com",
        help="Hostname to inspect."
    )

    parser.add_argument(
        "--port",
        type=int,
        default=443
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the handshake report as JSON."
    )

    parser.add_argument(
        "--openssl",
        action="store_true",
        help="Run an additional OpenSSL inspection."
    )

    args = parser.parse_args()

    try:
        config = TLSConfig(timeout=args.timeout)
        inspector = TLSInspector(config)

        report = inspector.inspect(args.host, args.port)

        if args.json:
            print(json.dumps(asdict(report), indent=2))
        else:
            print("\nTLS Handshake Report")
            print("-" * 75)

            for key, value in asdict(report).items():
                print(f"{key:25}: {value}")

        if report.state == HandshakeState.ESTABLISHED.value:
            violations = TLSPolicy.evaluate(
                report.tls_version or "",
                report.cipher_name or ""
            )

            print("\nSecurity Policy")
            if violations:
                for violation in violations:
                    print(f"FAIL: {violation}")
            else:
                print("PASS: Negotiated protocol and cipher meet local policy.")

        if args.openssl:
            output = inspect_certificate_with_openssl(
                args.host,
                args.port
            )

            if output:
                print("\nOpenSSL Diagnostic")
                print(output)

        display_supported_ciphers()
        demonstrate_session_concepts()

        return (
            0
            if report.state == HandshakeState.ESTABLISHED.value
            else 1
        )

    except (ValueError, ssl.SSLError) as exc:
        logger.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
