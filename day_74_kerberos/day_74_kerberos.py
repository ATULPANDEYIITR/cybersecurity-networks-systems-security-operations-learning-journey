#!/usr/bin/env python3
"""
KERBEROS AUTHENTICATION SIMULATOR
Educational implementation of:
- Key Distribution Center (KDC)
- Authentication Server (AS)
- Ticket Granting Server (TGS)
- Ticket Granting Tickets (TGT)
- Service Tickets (ST)
- Client and service authentication
- Pre-authentication
- Ticket expiration
- Replay protection
- Mutual authentication
- Authentication auditing

Uses HMAC-SHA256 for ticket integrity, not production Kerberos encryption.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class KerberosError(Exception):
    """Base exception for authentication failures."""


class AuthenticationError(KerberosError):
    pass


class TicketExpiredError(KerberosError):
    pass


class ReplayError(KerberosError):
    pass


class PrincipalNotFoundError(KerberosError):
    pass


class TicketType(Enum):
    TGT = "TGT"
    SERVICE = "SERVICE"


class AuthenticationState(Enum):
    REGISTERED = "REGISTERED"
    AUTHENTICATED = "AUTHENTICATED"
    SERVICE_AUTHENTICATED = "SERVICE_AUTHENTICATED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class Principal:
    name: str
    password_key: bytes
    roles: tuple[str, ...] = ()


@dataclass
class AuditEvent:
    timestamp: float
    event: str
    principal: str
    service: str
    result: str
    details: str = ""


@dataclass
class AuthenticationSession:
    client: str
    state: AuthenticationState = AuthenticationState.REGISTERED
    tgt: str | None = None
    service_tickets: dict[str, str] = field(default_factory=dict)


class ReplayCache:
    """Tracks previously accepted authenticators."""

    def __init__(self):
        self.entries: dict[str, float] = {}

    def check_and_store(self, identifier: str, expiry: float) -> None:
        now = time.time()

        self.entries = {
            key: value
            for key, value in self.entries.items()
            if value > now
        }

        if identifier in self.entries:
            raise ReplayError("Authenticator replay detected")

        self.entries[identifier] = expiry


class TicketCodec:
    """
    Creates authenticated ticket envelopes.

    Payloads are Base64 encoded for transport and HMAC authenticated.
    Base64 is NOT encryption. Real Kerberos encrypts ticket contents
    using the appropriate principal or service long-term key.
    """

    @staticmethod
    def encode(payload: dict[str, Any], signing_key: bytes) -> str:
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":")
        ).encode()

        signature = hmac.new(
            signing_key,
            raw,
            hashlib.sha256
        ).digest()

        envelope = {
            "payload": base64.b64encode(raw).decode(),
            "signature": base64.b64encode(signature).decode()
        }

        return base64.urlsafe_b64encode(
            json.dumps(envelope).encode()
        ).decode()

    @staticmethod
    def decode(ticket: str, signing_key: bytes) -> dict[str, Any]:
        try:
            envelope = json.loads(
                base64.urlsafe_b64decode(ticket.encode())
            )

            raw = base64.b64decode(envelope["payload"])
            supplied_signature = base64.b64decode(
                envelope["signature"]
            )

            expected_signature = hmac.new(
                signing_key,
                raw,
                hashlib.sha256
            ).digest()

            if not hmac.compare_digest(
                supplied_signature,
                expected_signature
            ):
                raise AuthenticationError("Invalid ticket signature")

            return json.loads(raw)

        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError("Malformed ticket") from exc


class KerberosKDC:
    """
    Simplified Key Distribution Center.

    AS:
        Issues Ticket Granting Tickets.

    TGS:
        Issues service tickets after validating a TGT.

    KDC:
        Maintains principal and service long-term keys.
    """

    def __init__(self, realm: str, ticket_lifetime: int = 300):
        if not realm or not realm.endswith(".LOCAL"):
            raise ValueError("Realm must be a valid .LOCAL realm")

        if ticket_lifetime <= 0:
            raise ValueError("Ticket lifetime must be positive")

        self.realm = realm
        self.ticket_lifetime = ticket_lifetime

        self.principals: dict[str, Principal] = {}
        self.services: dict[str, bytes] = {}

        self.tgs_key = secrets.token_bytes(32)
        self.replay_cache = ReplayCache()
        self.audit_log: list[AuditEvent] = []

    def _audit(
        self,
        event: str,
        principal: str,
        service: str,
        result: str,
        details: str = ""
    ) -> None:
        self.audit_log.append(
            AuditEvent(
                time.time(),
                event,
                principal,
                service,
                result,
                details
            )
        )

    def register_principal(
        self,
        name: str,
        password: str,
        roles: tuple[str, ...] = ()
    ) -> None:
        if not name or "@" not in name:
            raise ValueError("Principal must include a realm")

        if name in self.principals:
            raise ValueError("Principal already exists")

        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters")

        salt = secrets.token_bytes(16)

        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            200_000,
            dklen=32
        )

        # The salt is included in the stored verifier.
        stored_key = salt + key

        self.principals[name] = Principal(
            name,
            stored_key,
            roles
        )

        self._audit(
            "PRINCIPAL_REGISTERED",
            name,
            "KDC",
            "SUCCESS"
        )

    def register_service(self, service: str) -> None:
        if not service or "/" not in service:
            raise ValueError("Service must use service/hostname format")

        if service in self.services:
            raise ValueError("Service already registered")

        self.services[service] = secrets.token_bytes(32)

        self._audit(
            "SERVICE_REGISTERED",
            service,
            service,
            "SUCCESS"
        )

    def _verify_password(self, principal: str, password: str) -> None:
        record = self.principals.get(principal)

        if record is None:
            raise PrincipalNotFoundError(principal)

        salt = record.password_key[:16]
        expected = record.password_key[16:]

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            200_000,
            dklen=32
        )

        if not hmac.compare_digest(candidate, expected):
            raise AuthenticationError("Invalid credentials")

    def authenticate_as(
        self,
        principal: str,
        password: str
    ) -> str:
        """AS-REQ / AS-REP educational exchange."""

        try:
            self._verify_password(principal, password)

            now = time.time()
            session_key = secrets.token_bytes(32)

            payload = {
                "type": TicketType.TGT.value,
                "client": principal,
                "realm": self.realm,
                "issued_at": now,
                "expires_at": now + self.ticket_lifetime,
                "session_key": base64.b64encode(
                    session_key
                ).decode(),
                "ticket_id": secrets.token_hex(16)
            }

            tgt = TicketCodec.encode(payload, self.tgs_key)

            self._audit(
                "TGT_ISSUED",
                principal,
                "TGS",
                "SUCCESS"
            )

            return tgt

        except KerberosError as exc:
            self._audit(
                "AS_AUTHENTICATION",
                principal,
                "AS",
                "FAILED",
                str(exc)
            )
            raise

    def request_service_ticket(
        self,
        tgt: str,
        client: str,
        service: str
    ) -> tuple[str, bytes]:
        """TGS-REQ / TGS-REP educational exchange."""

        try:
            if service not in self.services:
                raise PrincipalNotFoundError(
                    f"Unknown service: {service}"
                )

            tgt_data = TicketCodec.decode(tgt, self.tgs_key)

            if tgt_data.get("type") != TicketType.TGT.value:
                raise AuthenticationError("Expected a TGT")

            if tgt_data.get("client") != client:
                raise AuthenticationError("TGT client mismatch")

            if tgt_data.get("realm") != self.realm:
                raise AuthenticationError("Realm mismatch")

            if time.time() >= tgt_data["expires_at"]:
                raise TicketExpiredError("TGT expired")

            service_session_key = secrets.token_bytes(32)
            now = time.time()

            payload = {
                "type": TicketType.SERVICE.value,
                "client": client,
                "service": service,
                "issued_at": now,
                "expires_at": min(
                    now + self.ticket_lifetime,
                    tgt_data["expires_at"]
                ),
                "session_key": base64.b64encode(
                    service_session_key
                ).decode(),
                "ticket_id": secrets.token_hex(16)
            }

            service_ticket = TicketCodec.encode(
                payload,
                self.services[service]
            )

            self._audit(
                "SERVICE_TICKET_ISSUED",
                client,
                service,
                "SUCCESS"
            )

            return service_ticket, service_session_key

        except KerberosError as exc:
            self._audit(
                "TGS_AUTHENTICATION",
                client,
                service,
                "FAILED",
                str(exc)
            )
            raise

    def validate_service_ticket(
        self,
        ticket: str,
        service: str,
        authenticator: dict[str, Any]
    ) -> str:
        """
        Service-side ticket validation.

        Checks:
        - Ticket signature
        - Service identity
        - Expiration
        - Authenticator timestamp
        - Replay detection
        """

        if service not in self.services:
            raise PrincipalNotFoundError(service)

        ticket_data = TicketCodec.decode(
            ticket,
            self.services[service]
        )

        if ticket_data.get("type") != TicketType.SERVICE.value:
            raise AuthenticationError("Not a service ticket")

        if ticket_data.get("service") != service:
            raise AuthenticationError("Wrong service")

        if time.time() >= ticket_data["expires_at"]:
            raise TicketExpiredError("Service ticket expired")

        session_key = base64.b64decode(
            ticket_data["session_key"]
        )

        try:
            client = ticket_data["client"]
            timestamp = float(authenticator["timestamp"])
            nonce = authenticator["nonce"]
            signature = authenticator["signature"]

            if not isinstance(nonce, str) or not nonce:
                raise ValueError("Invalid nonce")

            message = f"{client}|{service}|{timestamp}|{nonce}"

            expected = hmac.new(
                session_key,
                message.encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected):
                raise AuthenticationError("Invalid authenticator")

            if abs(time.time() - timestamp) > 60:
                raise AuthenticationError(
                    "Authenticator outside clock tolerance"
                )

            self.replay_cache.check_and_store(
                f"{ticket_data['ticket_id']}:{nonce}",
                ticket_data["expires_at"]
            )

            self._audit(
                "SERVICE_AUTHENTICATION",
                client,
                service,
                "SUCCESS"
            )

            # This value is a service proof, not a full RFC 4120 AP-REP.
            return hmac.new(
                session_key,
                f"SERVER|{client}|{service}|{nonce}".encode(),
                hashlib.sha256
            ).hexdigest()

        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError(
                "Malformed authenticator"
            ) from exc

    def create_authenticator(
        self,
        client: str,
        service: str,
        session_key: bytes
    ) -> dict[str, Any]:
        timestamp = time.time()
        nonce = secrets.token_hex(16)

        message = f"{client}|{service}|{timestamp}|{nonce}"

        signature = hmac.new(
            session_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return {
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature
        }

    def verify_server_proof(
        self,
        client: str,
        service: str,
        nonce: str,
        session_key: bytes,
        proof: str
    ) -> bool:
        expected = hmac.new(
            session_key,
            f"SERVER|{client}|{service}|{nonce}".encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(proof, expected)


class KerberosClient:
    """Client-side ticket management."""

    def __init__(self, principal: str, kdc: KerberosKDC):
        self.principal = principal
        self.kdc = kdc
        self.session = AuthenticationSession(principal)

    def login(self, password: str) -> None:
        self.session.tgt = self.kdc.authenticate_as(
            self.principal,
            password
        )

        self.session.state = AuthenticationState.AUTHENTICATED

    def access_service(self, service: str) -> bool:
        if not self.session.tgt:
            raise AuthenticationError("Login required")

        ticket, session_key = self.kdc.request_service_ticket(
            self.session.tgt,
            self.principal,
            service
        )

        authenticator = self.kdc.create_authenticator(
            self.principal,
            service,
            session_key
        )

        proof = self.kdc.validate_service_ticket(
            ticket,
            service,
            authenticator
        )

        verified = self.kdc.verify_server_proof(
            self.principal,
            service,
            authenticator["nonce"],
            session_key,
            proof
        )

        if not verified:
            raise AuthenticationError("Server authentication failed")

        self.session.service_tickets[service] = ticket
        self.session.state = AuthenticationState.SERVICE_AUTHENTICATED

        return True


def run_demo() -> None:
    print("=" * 65)
    print("KERBEROS AUTHENTICATION SIMULATOR")
    print("=" * 65)

    kdc = KerberosKDC("EXAMPLE.LOCAL", ticket_lifetime=300)

    user = "alice@EXAMPLE.LOCAL"
    password = "StrongPassword2026!"

    kdc.register_principal(
        user,
        password,
        ("developer", "employee")
    )

    kdc.register_service("http/server.example.local")
    kdc.register_service("postgres/db.example.local")

    client = KerberosClient(user, kdc)

    print("\n1. AS: Client requests authentication")
    client.login(password)
    print("   TGT issued successfully")

    print("\n2. TGS: Client requests HTTP service ticket")
    success = client.access_service("http/server.example.local")
    print(f"   Service authentication: {success}")

    print("\n3. TGS: Client requests database service ticket")
    success = client.access_service("postgres/db.example.local")
    print(f"   Database authentication: {success}")

    print("\n4. Negative test: Incorrect password")

    try:
        kdc.authenticate_as(user, "IncorrectPassword")
    except AuthenticationError as exc:
        print(f"   Authentication rejected: {exc}")

    print("\n5. Negative test: Replayed authenticator")

    ticket, session_key = kdc.request_service_ticket(
        client.session.tgt,
        user,
        "http/server.example.local"
    )

    authenticator = kdc.create_authenticator(
        user,
        "http/server.example.local",
        session_key
    )

    kdc.validate_service_ticket(
        ticket,
        "http/server.example.local",
        authenticator
    )

    try:
        kdc.validate_service_ticket(
            ticket,
            "http/server.example.local",
            authenticator
        )
    except ReplayError as exc:
        print(f"   Replay rejected: {exc}")

    print("\n6. Authentication audit")

    for event in kdc.audit_log:
        print(
            f"{event.event:28} "
            f"{event.principal:30} "
            f"{event.result}"
        )

    print("\nSimulation completed.")


if __name__ == "__main__":
    run_demo()
