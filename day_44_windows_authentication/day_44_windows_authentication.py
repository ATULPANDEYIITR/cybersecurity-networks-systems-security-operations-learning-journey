#!/usr/bin/env python3
"""
Windows Authentication: Local Accounts, NTLM, Kerberos, and Authentication Flows

A self-contained educational simulator for understanding Windows-style
authentication architecture and security decisions.

This program does not authenticate against Windows, contact a domain
controller, implement NTLM cryptography, issue Kerberos tickets, or access
Windows credential stores. It models the protocol concepts and selected
security checks using synthetic identities, challenges, tickets, and policies.

Run:
    python windows_authentication.py
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AuthenticationError(Exception):
    """Raised when an authentication flow cannot be completed."""


class AuthorizationError(Exception):
    """Raised when an authenticated identity lacks permission."""


class AccountType(Enum):
    LOCAL = "local"
    DOMAIN = "domain"
    SERVICE = "service"


class AuthenticationProtocol(Enum):
    LOCAL = "local account authentication"
    NTLM = "NTLM challenge-response"
    KERBEROS = "Kerberos ticket authentication"


class LogonType(Enum):
    INTERACTIVE = "interactive"
    NETWORK = "network"
    SERVICE = "service"
    REMOTE_INTERACTIVE = "remote interactive"


@dataclass
class Account:
    username: str
    account_type: AccountType
    password_verifier: bytes
    domain: Optional[str] = None
    enabled: bool = True
    locked: bool = False
    groups: set[str] = field(default_factory=set)
    failed_attempts: int = 0

    @property
    def principal(self) -> str:
        if self.domain:
            return f"{self.username}@{self.domain.upper()}"
        return f"{self.username}@LOCALHOST"


@dataclass(frozen=True)
class AuthenticatedSession:
    principal: str
    protocol: AuthenticationProtocol
    logon_type: LogonType
    issued_at: float
    session_id: str
    groups: frozenset[str]


@dataclass(frozen=True)
class AuditEvent:
    timestamp: float
    event_type: str
    principal: str
    outcome: str
    detail: str


class AuditLog:
    """Records authentication outcomes without recording passwords."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(
        self,
        event_type: str,
        principal: str,
        outcome: str,
        detail: str,
    ) -> None:
        self.events.append(
            AuditEvent(
                timestamp=time.time(),
                event_type=event_type,
                principal=principal,
                outcome=outcome,
                detail=detail,
            )
        )

    def display(self) -> None:
        for event in self.events:
            print(
                f"[{event.event_type}] {event.principal} | "
                f"{event.outcome} | {event.detail}"
            )


class AccountDirectory:
    """
    Educational account directory.

    Password verifiers use scrypt with unique salts. This is not the
    Windows NT password-hash format and cannot validate real Windows
    NTLM responses.
    """

    def __init__(self, salt_length: int = 16) -> None:
        self.accounts: dict[str, Account] = {}
        self.salt_length = salt_length
        self._salts: dict[str, bytes] = {}

    @staticmethod
    def normalize(username: str, domain: Optional[str]) -> str:
        return (
            f"{domain.upper()}\\{username.casefold()}"
            if domain
            else f"LOCALHOST\\{username.casefold()}"
        )

    def add_account(
        self,
        username: str,
        password: str,
        account_type: AccountType,
        domain: Optional[str] = None,
        groups: Optional[set[str]] = None,
    ) -> Account:
        if not username.strip():
            raise ValueError("Username cannot be empty.")
        if not password:
            raise ValueError("Password cannot be empty.")
        if account_type == AccountType.DOMAIN and not domain:
            raise ValueError("Domain accounts require a domain.")
        if account_type == AccountType.LOCAL and domain:
            raise ValueError("Local accounts must not specify a domain.")

        key = self.normalize(username, domain)
        if key in self.accounts:
            raise ValueError(f"Account already exists: {key}")

        salt = secrets.token_bytes(self.salt_length)
        verifier = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )

        account = Account(
            username=username,
            account_type=account_type,
            password_verifier=verifier,
            domain=domain,
            groups=set(groups or ()),
        )
        self.accounts[key] = account
        self._salts[key] = salt
        return account

    def get(self, username: str, domain: Optional[str] = None) -> Account:
        key = self.normalize(username, domain)
        try:
            return self.accounts[key]
        except KeyError as exc:
            raise AuthenticationError("Account not found.") from exc

    def verify_password(
        self,
        account: Account,
        supplied_password: str,
    ) -> bool:
        key = self.normalize(account.username, account.domain)
        candidate = hashlib.scrypt(
            supplied_password.encode("utf-8"),
            salt=self._salts[key],
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )
        return hmac.compare_digest(candidate, account.password_verifier)


class LocalAuthenticator:
    """
    Simulates a local logon validated by the machine's local account
    authority. It does not call Windows LSA or the real SAM database.
    """

    def __init__(
        self,
        directory: AccountDirectory,
        audit: AuditLog,
        lockout_threshold: int = 3,
    ) -> None:
        if lockout_threshold < 1:
            raise ValueError("Lockout threshold must be positive.")
        self.directory = directory
        self.audit = audit
        self.lockout_threshold = lockout_threshold

    def authenticate(
        self,
        username: str,
        password: str,
        logon_type: LogonType = LogonType.INTERACTIVE,
    ) -> AuthenticatedSession:
        try:
            account = self.directory.get(username)
        except AuthenticationError:
            self.audit.record(
                "local_logon",
                f"LOCALHOST\\{username}",
                "denied",
                "Unknown local account",
            )
            raise

        if account.account_type != AccountType.LOCAL:
            raise AuthenticationError(
                "Local authentication accepts local accounts only."
            )

        if not account.enabled or account.locked:
            self.audit.record(
                "local_logon",
                account.principal,
                "denied",
                "Account disabled or locked",
            )
            raise AuthenticationError("Account is unavailable.")

        if not self.directory.verify_password(account, password):
            account.failed_attempts += 1
            if account.failed_attempts >= self.lockout_threshold:
                account.locked = True
            self.audit.record(
                "local_logon",
                account.principal,
                "denied",
                "Invalid credentials",
            )
            raise AuthenticationError("Invalid credentials.")

        account.failed_attempts = 0
        session = AuthenticatedSession(
            principal=account.principal,
            protocol=AuthenticationProtocol.LOCAL,
            logon_type=logon_type,
            issued_at=time.time(),
            session_id=secrets.token_hex(16),
            groups=frozenset(account.groups),
        )
        self.audit.record(
            "local_logon",
            account.principal,
            "success",
            f"Logon type: {logon_type.value}",
        )
        return session


@dataclass(frozen=True)
class NTLMChallenge:
    challenge_id: str
    server_name: str
    nonce: bytes
    created_at: float


class NtlmConceptSimulator:
    """
    Models the NTLM challenge-response exchange with HMAC-SHA256.

    Real NTLM commonly uses responses derived from an NT password hash
    and protocol-specific algorithms. This simulator intentionally uses
    different cryptography so that it cannot be mistaken for a working
    NTLM implementation.
    """

    def __init__(
        self,
        directory: AccountDirectory,
        audit: AuditLog,
        challenge_ttl: float = 60.0,
    ) -> None:
        if challenge_ttl <= 0:
            raise ValueError("Challenge lifetime must be positive.")
        self.directory = directory
        self.audit = audit
        self.challenge_ttl = challenge_ttl
        self._active_challenges: dict[str, NTLMChallenge] = {}

    def issue_challenge(self, server_name: str) -> NTLMChallenge:
        if not server_name.strip():
            raise ValueError("Server name cannot be empty.")

        challenge = NTLMChallenge(
            challenge_id=secrets.token_hex(12),
            server_name=server_name,
            nonce=secrets.token_bytes(32),
            created_at=time.time(),
        )
        self._active_challenges[challenge.challenge_id] = challenge
        return challenge

    def _response(
        self,
        password: str,
        challenge: NTLMChallenge,
        username: str,
        domain: str,
    ) -> bytes:
        # Domain and username binding prevents a response from being
        # reused for a different identity in this simplified protocol.
        key = hashlib.sha256(password.encode("utf-8")).digest()
        message = (
            challenge.nonce
            + b"|"
            + challenge.server_name.encode("utf-8")
            + b"|"
            + username.casefold().encode("utf-8")
            + b"|"
            + domain.upper().encode("utf-8")
        )
        return hmac.new(key, message, hashlib.sha256).digest()

    def create_client_response(
        self,
        username: str,
        domain: str,
        password: str,
        challenge: NTLMChallenge,
    ) -> bytes:
        """Creates a synthetic response for controlled demonstration."""
        return self._response(password, challenge, username, domain)

    def authenticate(
        self,
        username: str,
        domain: str,
        response: bytes,
        challenge_id: str,
        logon_type: LogonType = LogonType.NETWORK,
    ) -> AuthenticatedSession:
        challenge = self._active_challenges.pop(challenge_id, None)
        if challenge is None:
            raise AuthenticationError(
                "Challenge is unknown, expired, or already consumed."
            )

        if time.time() - challenge.created_at > self.challenge_ttl:
            self.audit.record(
                "ntlm_concept",
                f"{domain}\\{username}",
                "denied",
                "Challenge expired",
            )
            raise AuthenticationError("Challenge expired.")

        try:
            account = self.directory.get(username, domain)
        except AuthenticationError:
            self.audit.record(
                "ntlm_concept",
                f"{domain}\\{username}",
                "denied",
                "Unknown domain account",
            )
            raise

        if account.account_type != AccountType.DOMAIN:
            raise AuthenticationError(
                "This example accepts domain accounts only."
            )
        if not account.enabled or account.locked:
            raise AuthenticationError("Account is unavailable.")

        # This synthetic verifier reconstructs the demonstration response.
        # It does not use Windows NT hashes or implement real NTLM.
        password_not_available = None
        del password_not_available
        raise AuthenticationError(
            "Direct validation requires the account password in this "
            "educational simulator. Use authenticate_with_password() "
            "for the complete synthetic exchange."
        )

    def authenticate_with_password(
        self,
        username: str,
        domain: str,
        password: str,
        response: bytes,
        challenge_id: str,
    ) -> AuthenticatedSession:
        """
        Demonstration-only verifier. A real verifier would validate
        the response using the protocol's stored verifier and algorithms.
        """
        challenge = self._active_challenges.pop(challenge_id, None)
        principal = f"{domain.upper()}\\{username}"

        if challenge is None:
            raise AuthenticationError(
                "Challenge is unknown or already consumed."
            )
        if time.time() - challenge.created_at > self.challenge_ttl:
            raise AuthenticationError("Challenge expired.")

        account = self.directory.get(username, domain)
        if account.account_type != AccountType.DOMAIN:
            raise AuthenticationError("A domain account is required.")
        if not account.enabled or account.locked:
            raise AuthenticationError("Account is unavailable.")

        expected = self._response(
            password, challenge, username, domain
        )
        if not hmac.compare_digest(expected, response):
            self.audit.record(
                "ntlm_concept",
                principal,
                "denied",
                "Challenge-response mismatch",
            )
            raise AuthenticationError("Invalid challenge response.")

        session = AuthenticatedSession(
            principal=account.principal,
            protocol=AuthenticationProtocol.NTLM,
            logon_type=LogonType.NETWORK,
            issued_at=time.time(),
            session_id=secrets.token_hex(16),
            groups=frozenset(account.groups),
        )
        self.audit.record(
            "ntlm_concept",
            principal,
            "success",
            "Synthetic challenge-response accepted",
        )
        return session


@dataclass(frozen=True)
class KerberosTicket:
    ticket_id: str
    client_principal: str
    service_principal: str
    issued_at: float
    expires_at: float
    session_key: bytes
    ticket_kind: str


class KerberosConceptSimulator:
    """
    Models the roles of a Key Distribution Center (KDC), Ticket Granting
    Ticket (TGT), service ticket, and service validation.

    Tickets and session keys are synthetic. This is not Kerberos wire
    protocol, ASN.1, PAC, encryption, or Active Directory integration.
    """

    def __init__(
        self,
        directory: AccountDirectory,
        audit: AuditLog,
        ticket_lifetime: float = 300.0,
        clock_skew_tolerance: float = 30.0,
    ) -> None:
        if ticket_lifetime <= 0:
            raise ValueError("Ticket lifetime must be positive.")
        if clock_skew_tolerance < 0:
            raise ValueError("Clock skew tolerance cannot be negative.")
        self.directory = directory
        self.audit = audit
        self.ticket_lifetime = ticket_lifetime
        self.clock_skew_tolerance = clock_skew_tolerance
        self._tickets: dict[str, KerberosTicket] = {}

    def request_tgt(
        self,
        username: str,
        domain: str,
        password: str,
    ) -> KerberosTicket:
        account = self.directory.get(username, domain)
        principal = account.principal

        if account.account_type != AccountType.DOMAIN:
            raise AuthenticationError("A domain account is required.")
        if not account.enabled or account.locked:
            raise AuthenticationError("Account is unavailable.")
        if not self.directory.verify_password(account, password):
            self.audit.record(
                "kerberos_as",
                principal,
                "denied",
                "Initial authentication failed",
            )
            raise AuthenticationError("Invalid credentials.")

        now = time.time()
        ticket = KerberosTicket(
            ticket_id=secrets.token_hex(16),
            client_principal=principal,
            service_principal=f"krbtgt/{domain.upper()}",
            issued_at=now,
            expires_at=now + self.ticket_lifetime,
            session_key=secrets.token_bytes(32),
            ticket_kind="TGT",
        )
        self._tickets[ticket.ticket_id] = ticket
        self.audit.record(
            "kerberos_as",
            principal,
            "success",
            "KDC issued synthetic TGT",
        )
        return ticket

    def request_service_ticket(
        self,
        tgt_id: str,
        service_principal: str,
    ) -> KerberosTicket:
        tgt = self._tickets.get(tgt_id)
        if tgt is None or tgt.ticket_kind != "TGT":
            raise AuthenticationError("Valid TGT not found.")
        if time.time() > tgt.expires_at:
            raise AuthenticationError("TGT has expired.")
        if not service_principal.strip() or "/" not in service_principal:
            raise AuthenticationError(
                "Use a service principal such as HTTP/app.example.com."
            )

        service_ticket = KerberosTicket(
            ticket_id=secrets.token_hex(16),
            client_principal=tgt.client_principal,
            service_principal=service_principal,
            issued_at=time.time(),
            expires_at=min(
                tgt.expires_at,
                time.time() + self.ticket_lifetime,
            ),
            session_key=secrets.token_bytes(32),
            ticket_kind="SERVICE",
        )
        self._tickets[service_ticket.ticket_id] = service_ticket
        self.audit.record(
            "kerberos_tgs",
            tgt.client_principal,
            "success",
            f"Service ticket issued for {service_principal}",
        )
        return service_ticket

    def validate_service_ticket(
        self,
        ticket_id: str,
        expected_service: str,
    ) -> AuthenticatedSession:
        ticket = self._tickets.get(ticket_id)
        if ticket is None or ticket.ticket_kind != "SERVICE":
            raise AuthenticationError("Service ticket not found.")
        if time.time() > ticket.expires_at:
            raise AuthenticationError("Service ticket has expired.")
        if not hmac.compare_digest(
            ticket.service_principal.encode(),
            expected_service.encode(),
        ):
            raise AuthenticationError("Ticket service does not match.")

        account_name, separator, domain = (
            ticket.client_principal.partition("@")
        )
        if not separator:
            raise AuthenticationError("Malformed client principal.")

        username = account_name.rsplit("\\", 1)[-1]
        account = self.directory.get(username, domain)
        if not account.enabled or account.locked:
            raise AuthenticationError("Account is unavailable.")

        session = AuthenticatedSession(
            principal=ticket.client_principal,
            protocol=AuthenticationProtocol.KERBEROS,
            logon_type=LogonType.NETWORK,
            issued_at=time.time(),
            session_id=secrets.token_hex(16),
            groups=frozenset(account.groups),
        )
        self.audit.record(
            "kerberos_service",
            ticket.client_principal,
            "success",
            f"Accepted ticket for {expected_service}",
        )
        return session


class ResourcePolicy:
    """Separates authentication from authorization."""

    def __init__(self) -> None:
        self.permissions: dict[str, set[str]] = {}

    def grant(self, group: str, resource: str) -> None:
        self.permissions.setdefault(group, set()).add(resource)

    def authorize(
        self,
        session: AuthenticatedSession,
        resource: str,
    ) -> bool:
        permitted = any(
            resource in self.permissions.get(group, set())
            for group in session.groups
        )
        if not permitted:
            raise AuthorizationError(
                f"{session.principal} authenticated but cannot access "
                f"{resource}."
            )
        return True


def demonstrate_local_authentication(
    directory: AccountDirectory,
    audit: AuditLog,
) -> AuthenticatedSession:
    print("\n=== Local account authentication ===")
    authenticator = LocalAuthenticator(directory, audit)

    session = authenticator.authenticate(
        "helpdesk",
        "LocalPass!2026",
        LogonType.INTERACTIVE,
    )
    print("Authenticated:", session.principal)
    print("Protocol:", session.protocol.value)

    try:
        authenticator.authenticate("helpdesk", "wrong-password")
    except AuthenticationError as exc:
        print("Expected rejection:", exc)

    return session


def demonstrate_ntlm_concepts(
    directory: AccountDirectory,
    audit: AuditLog,
) -> AuthenticatedSession:
    print("\n=== NTLM challenge-response concept ===")
    ntlm = NtlmConceptSimulator(directory, audit)
    challenge = ntlm.issue_challenge("fileserver.corp.example")
    print("Server issued a fresh challenge.")

    response = ntlm.create_client_response(
        "alex",
        "CORP.EXAMPLE",
        "DomainPass!2026",
        challenge,
    )
    session = ntlm.authenticate_with_password(
        "alex",
        "CORP.EXAMPLE",
        "DomainPass!2026",
        response,
        challenge.challenge_id,
    )
    print("Challenge-response accepted:", session.principal)

    try:
        ntlm.authenticate_with_password(
            "alex",
            "CORP.EXAMPLE",
            "DomainPass!2026",
            response,
            challenge.challenge_id,
        )
    except AuthenticationError as exc:
        print("Replay with consumed challenge rejected:", exc)

    return session


def demonstrate_kerberos(
    directory: AccountDirectory,
    audit: AuditLog,
) -> AuthenticatedSession:
    print("\n=== Kerberos ticket concept ===")
    kerberos = KerberosConceptSimulator(directory, audit)

    tgt = kerberos.request_tgt(
        "alex",
        "CORP.EXAMPLE",
        "DomainPass!2026",
    )
    print("KDC issued:", tgt.ticket_kind)

    service_ticket = kerberos.request_service_ticket(
        tgt.ticket_id,
        "HTTP/intranet.corp.example",
    )
    print("KDC issued:", service_ticket.ticket_kind)

    session = kerberos.validate_service_ticket(
        service_ticket.ticket_id,
        "HTTP/intranet.corp.example",
    )
    print("Service accepted ticket:", session.principal)

    try:
        kerberos.validate_service_ticket(
            service_ticket.ticket_id,
            "CIFS/fileserver.corp.example",
        )
    except AuthenticationError as exc:
        print("Wrong service rejected:", exc)

    return session


def demonstrate_authorization(
    session: AuthenticatedSession,
) -> None:
    print("\n=== Authentication versus authorization ===")
    policy = ResourcePolicy()
    policy.grant("Domain Users", "intranet.read")
    policy.grant("IT Support", "password-reset")

    try:
        policy.authorize(session, "intranet.read")
        print("Resource access granted: intranet.read")
        policy.authorize(session, "payroll.admin")
    except AuthorizationError as exc:
        print("Resource access denied:", exc)


def main() -> None:
    print("Windows Authentication Architecture Simulator")
    print("All identities and protocol artifacts are synthetic.")

    audit = AuditLog()
    directory = AccountDirectory()

    directory.add_account(
        "helpdesk",
        "LocalPass!2026",
        AccountType.LOCAL,
        groups={"Users", "IT Support"},
    )
    directory.add_account(
        "alex",
        "DomainPass!2026",
        AccountType.DOMAIN,
        domain="CORP.EXAMPLE",
        groups={"Domain Users"},
    )

    local_session = demonstrate_local_authentication(directory, audit)
    ntlm_session = demonstrate_ntlm_concepts(directory, audit)
    kerberos_session = demonstrate_kerberos(directory, audit)

    demonstrate_authorization(kerberos_session)

    print("\n=== Session comparison ===")
    for session in (local_session, ntlm_session, kerberos_session):
        print(
            f"{session.principal}: {session.protocol.value}, "
            f"{session.logon_type.value}, "
            f"groups={sorted(session.groups)}"
        )

    print("\n=== Audit events ===")
    audit.display()

    print(
        "\nSecurity boundary: actual Windows authentication requires "
        "Windows security components, domain infrastructure, and "
        "protocol-compliant cryptographic processing."
    )


if __name__ == "__main__":
    main()
