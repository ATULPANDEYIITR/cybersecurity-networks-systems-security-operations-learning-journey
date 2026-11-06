#!/usr/bin/env python3
"""
Public Key Infrastructure (PKI)
Certificate Authorities, Root CAs, Intermediate CAs, and Certificate Lifecycle.

This executable model demonstrates:
- Root and intermediate certificate authorities.
- Certificate issuance and hierarchical trust.
- Certificate validity and expiration.
- Certificate revocation and CRL-style status checking.
- Certificate renewal and replacement.
- Chain-of-trust validation.
- CA constraints, key usage, and issuance policies.
- Audit logging and failure handling.

The program models PKI lifecycle and governance. It does not replace
X.509 signature verification or cryptographic certificate processing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional
import hashlib
import secrets


class CertificateError(Exception):
    """Base exception for certificate operations."""


class ValidationError(CertificateError):
    pass


class IssuanceError(CertificateError):
    pass


class RevocationError(CertificateError):
    pass


class CAType(Enum):
    ROOT = "ROOT"
    INTERMEDIATE = "INTERMEDIATE"
    END_ENTITY = "END_ENTITY"


class CertificateStatus(Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    NOT_YET_VALID = "NOT_YET_VALID"


class RevocationReason(Enum):
    KEY_COMPROMISE = "KEY_COMPROMISE"
    CA_COMPROMISE = "CA_COMPROMISE"
    SUPERSEDED = "SUPERSEDED"
    CESSATION_OF_OPERATION = "CESSATION_OF_OPERATION"
    PRIVILEGE_WITHDRAWN = "PRIVILEGE_WITHDRAWN"


@dataclass
class AuditEvent:
    timestamp: datetime
    action: str
    certificate_id: str
    details: str


@dataclass
class Certificate:
    certificate_id: str
    serial_number: str
    subject: str
    issuer_id: Optional[str]
    ca_type: CAType
    not_before: datetime
    not_after: datetime
    is_ca: bool
    max_path_length: Optional[int]
    key_usage: set[str]
    subject_key_id: str
    authority_key_id: Optional[str]
    signature_algorithm: str
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[RevocationReason] = None
    replacement_id: Optional[str] = None

    def status(self, now: datetime) -> CertificateStatus:
        if self.revoked_at is not None:
            return CertificateStatus.REVOKED
        if now < self.not_before:
            return CertificateStatus.NOT_YET_VALID
        if now >= self.not_after:
            return CertificateStatus.EXPIRED
        return CertificateStatus.ACTIVE


@dataclass
class CertificateAuthority:
    certificate: Certificate
    max_validity_days: int
    active: bool = True
    issued_certificates: set[str] = field(default_factory=set)


class PKIManager:
    """Manages a certificate hierarchy and its lifecycle."""

    def __init__(self, organization: str):
        self.organization = organization
        self.certificates: dict[str, Certificate] = {}
        self.authorities: dict[str, CertificateAuthority] = {}
        self.trust_anchors: set[str] = set()
        self.audit_log: list[AuditEvent] = []
        self.revocation_registry: dict[str, RevocationReason] = {}

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def fingerprint(subject: str, serial: str) -> str:
        return hashlib.sha256(
            f"{subject}:{serial}".encode()
        ).hexdigest()

    def _record(self, action: str, cert_id: str, details: str) -> None:
        self.audit_log.append(
            AuditEvent(self.now(), action, cert_id, details)
        )

    def _register(self, certificate: Certificate) -> None:
        if certificate.certificate_id in self.certificates:
            raise CertificateError("Duplicate certificate identifier.")

        self.certificates[certificate.certificate_id] = certificate

    def create_root_ca(
        self,
        subject: str,
        validity_days: int = 3650,
        max_path_length: int = 2,
    ) -> Certificate:
        if validity_days <= 0 or max_path_length < 0:
            raise ValidationError("Invalid root CA configuration.")

        now = self.now()
        serial = secrets.token_hex(16).upper()
        cert_id = f"ROOT-{serial[:12]}"

        certificate = Certificate(
            certificate_id=cert_id,
            serial_number=serial,
            subject=subject,
            issuer_id=None,
            ca_type=CAType.ROOT,
            not_before=now,
            not_after=now + timedelta(days=validity_days),
            is_ca=True,
            max_path_length=max_path_length,
            key_usage={"key_cert_sign", "crl_sign"},
            subject_key_id=self.fingerprint(subject, serial),
            authority_key_id=None,
            signature_algorithm="SHA256-RSA-SIMULATION",
        )

        self._register(certificate)

        self.authorities[cert_id] = CertificateAuthority(
            certificate, validity_days
        )

        self.trust_anchors.add(cert_id)

        self._record("ROOT_CREATED", cert_id, subject)
        return certificate

    def create_intermediate_ca(
        self,
        parent_id: str,
        subject: str,
        validity_days: int = 730,
        max_path_length: int = 1,
    ) -> Certificate:
        parent = self._get_authority(parent_id)
        self._validate_ca(parent.certificate, self.now())

        if not parent.certificate.is_ca:
            raise IssuanceError("Parent is not a CA.")

        if parent.certificate.max_path_length is not None:
            if parent.certificate.max_path_length <= 0:
                raise IssuanceError("Parent path length constraint exceeded.")

        if validity_days <= 0 or max_path_length < 0:
            raise ValidationError("Invalid intermediate CA configuration.")

        now = self.now()
        serial = secrets.token_hex(16).upper()
        cert_id = f"INT-{serial[:12]}"

        expiry = min(
            now + timedelta(days=validity_days),
            parent.certificate.not_after,
        )

        if expiry <= now:
            raise IssuanceError("Parent certificate expires too soon.")

        certificate = Certificate(
            certificate_id=cert_id,
            serial_number=serial,
            subject=subject,
            issuer_id=parent_id,
            ca_type=CAType.INTERMEDIATE,
            not_before=now,
            not_after=expiry,
            is_ca=True,
            max_path_length=max_path_length,
            key_usage={"key_cert_sign", "crl_sign"},
            subject_key_id=self.fingerprint(subject, serial),
            authority_key_id=parent.certificate.subject_key_id,
            signature_algorithm="SHA256-RSA-SIMULATION",
        )

        self._register(certificate)

        self.authorities[cert_id] = CertificateAuthority(
            certificate, validity_days
        )

        parent.issued_certificates.add(cert_id)

        self._record("INTERMEDIATE_CREATED", cert_id, parent_id)
        return certificate

    def issue_certificate(
        self,
        issuer_id: str,
        subject: str,
        validity_days: int = 90,
        key_usage: Optional[set[str]] = None,
    ) -> Certificate:
        issuer = self._get_authority(issuer_id)
        issuer_cert = issuer.certificate
        now = self.now()

        self._validate_ca(issuer_cert, now)

        if validity_days <= 0:
            raise ValidationError("Validity must be positive.")

        if validity_days > issuer.max_validity_days:
            raise IssuanceError("CA maximum validity period exceeded.")

        if not subject.strip():
            raise ValidationError("Subject cannot be empty.")

        usage = key_usage or {"digital_signature", "key_encipherment"}

        allowed_usage = {
            "digital_signature",
            "key_encipherment",
            "key_agreement",
            "data_encipherment",
            "content_commitment",
        }

        if not usage or not usage.issubset(allowed_usage):
            raise ValidationError("Invalid end-entity key usage.")

        serial = secrets.token_hex(16).upper()
        cert_id = f"LEAF-{serial[:12]}"

        expiry = min(
            now + timedelta(days=validity_days),
            issuer_cert.not_after,
        )

        certificate = Certificate(
            certificate_id=cert_id,
            serial_number=serial,
            subject=subject,
            issuer_id=issuer_id,
            ca_type=CAType.END_ENTITY,
            not_before=now,
            not_after=expiry,
            is_ca=False,
            max_path_length=None,
            key_usage=set(usage),
            subject_key_id=self.fingerprint(subject, serial),
            authority_key_id=issuer_cert.subject_key_id,
            signature_algorithm="SHA256-RSA-SIMULATION",
        )

        self._register(certificate)
        issuer.issued_certificates.add(cert_id)

        self._record("CERTIFICATE_ISSUED", cert_id, issuer_id)
        return certificate

    def _get_authority(self, authority_id: str) -> CertificateAuthority:
        authority = self.authorities.get(authority_id)

        if authority is None or not authority.active:
            raise IssuanceError("Unknown or inactive certificate authority.")

        return authority

    def _validate_ca(self, cert: Certificate, now: datetime) -> None:
        if not cert.is_ca:
            raise ValidationError("Certificate is not a CA.")

        if cert.status(now) != CertificateStatus.ACTIVE:
            raise ValidationError("CA certificate is not currently valid.")

        if "key_cert_sign" not in cert.key_usage:
            raise ValidationError("CA lacks certificate-signing usage.")

    def build_chain(self, certificate_id: str) -> list[Certificate]:
        certificate = self.certificates.get(certificate_id)

        if certificate is None:
            raise ValidationError("Certificate does not exist.")

        chain = []
        visited = set()
        current = certificate

        while True:
            if current.certificate_id in visited:
                raise ValidationError("Certificate chain contains a cycle.")

            visited.add(current.certificate_id)
            chain.append(current)

            if current.issuer_id is None:
                break

            parent = self.certificates.get(current.issuer_id)

            if parent is None:
                raise ValidationError("Issuer certificate is missing.")

            if current.authority_key_id != parent.subject_key_id:
                raise ValidationError("Authority key identifier mismatch.")

            current = parent

        return chain

    def validate_certificate(
        self,
        certificate_id: str,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        now = now or self.now()

        try:
            chain = self.build_chain(certificate_id)

            if chain[-1].certificate_id not in self.trust_anchors:
                raise ValidationError("Untrusted root certificate.")

            for index, cert in enumerate(chain):
                if cert.status(now) != CertificateStatus.ACTIVE:
                    raise ValidationError(
                        f"{cert.certificate_id}: {cert.status(now).value}"
                    )

                if index > 0:
                    parent = chain[index - 1]

                    if not cert.is_ca and index != 1:
                        raise ValidationError("Invalid chain structure.")

                    if cert.issuer_id != parent.certificate_id:
                        raise ValidationError("Issuer relationship mismatch.")

                if index > 0 and cert.is_ca:
                    parent = chain[index - 1]

                    if parent.max_path_length is not None:
                        subordinate_ca_count = sum(
                            1 for item in chain[:index]
                            if item.is_ca
                        )

                        if subordinate_ca_count > parent.max_path_length:
                            raise ValidationError(
                                "CA path length constraint exceeded."
                            )

            return True, "Certificate chain is structurally trusted."

        except CertificateError as exc:
            return False, str(exc)

    def revoke_certificate(
        self,
        certificate_id: str,
        reason: RevocationReason,
    ) -> None:
        certificate = self.certificates.get(certificate_id)

        if certificate is None:
            raise RevocationError("Certificate does not exist.")

        if certificate.revoked_at is not None:
            raise RevocationError("Certificate already revoked.")

        certificate.revoked_at = self.now()
        certificate.revocation_reason = reason

        self.revocation_registry[certificate_id] = reason

        self._record("CERTIFICATE_REVOKED", certificate_id, reason.value)

        # Revoking a CA makes certificates depending on its trust chain
        # unusable, even when individual descendants are not revoked.
        if certificate.is_ca and certificate_id in self.authorities:
            self.authorities[certificate_id].active = False

    def renew_certificate(
        self,
        certificate_id: str,
        validity_days: int = 90,
    ) -> Certificate:
        old = self.certificates.get(certificate_id)

        if old is None or old.ca_type != CAType.END_ENTITY:
            raise ValidationError("Only registered end-entity certificates can be renewed.")

        if old.status(self.now()) == CertificateStatus.REVOKED:
            raise ValidationError("A revoked certificate cannot be renewed.")

        new_certificate = self.issue_certificate(
            old.issuer_id,
            old.subject,
            validity_days,
            old.key_usage,
        )

        old.replacement_id = new_certificate.certificate_id

        self._record(
            "CERTIFICATE_RENEWED",
            certificate_id,
            new_certificate.certificate_id,
        )

        return new_certificate

    def certificate_report(self) -> None:
        print("\nCERTIFICATE INVENTORY")
        print("-" * 105)

        for cert in self.certificates.values():
            print(
                f"{cert.certificate_id:20} "
                f"{cert.ca_type.value:12} "
                f"{cert.subject:35} "
                f"{cert.status(self.now()).value:15}"
            )

    def audit_report(self) -> None:
        print("\nAUDIT EVENTS")

        for event in self.audit_log:
            print(
                event.timestamp.isoformat(),
                event.action,
                event.certificate_id,
                event.details,
            )


def demonstrate_pki() -> None:
    pki = PKIManager("Example Enterprise")

    print("PUBLIC KEY INFRASTRUCTURE LIFECYCLE")

    root = pki.create_root_ca(
        "CN=Example Enterprise Root CA",
        validity_days=3650,
        max_path_length=2,
    )

    intermediate = pki.create_intermediate_ca(
        root.certificate_id,
        "CN=Example Enterprise Issuing CA",
        validity_days=730,
        max_path_length=0,
    )

    server = pki.issue_certificate(
        intermediate.certificate_id,
        "DNS=api.example.com",
        validity_days=90,
        key_usage={"digital_signature", "key_encipherment"},
    )

    client = pki.issue_certificate(
        intermediate.certificate_id,
        "CN=application-client",
        validity_days=60,
        key_usage={"digital_signature"},
    )

    print("\nISSUANCE")
    print("Root:", root.certificate_id)
    print("Intermediate:", intermediate.certificate_id)
    print("Server:", server.certificate_id)
    print("Client:", client.certificate_id)

    valid, message = pki.validate_certificate(server.certificate_id)
    print("\nSERVER VALIDATION:", valid, message)

    print("\nCERTIFICATE CHAIN")

    for cert in pki.build_chain(server.certificate_id):
        print(cert.certificate_id, "->", cert.subject)

    renewed = pki.renew_certificate(server.certificate_id, 120)

    print("\nRENEWAL")
    print("Old certificate:", server.certificate_id)
    print("New certificate:", renewed.certificate_id)
    print("Replacement:", server.replacement_id)

    pki.revoke_certificate(
        client.certificate_id,
        RevocationReason.KEY_COMPROMISE,
    )

    valid, message = pki.validate_certificate(client.certificate_id)
    print("\nREVOKED CLIENT VALIDATION:", valid, message)

    pki.certificate_report()
    pki.audit_report()

    print("\nEDGE CASE TESTS")

    try:
        pki.issue_certificate(
            intermediate.certificate_id,
            "CN=invalid-client",
            validity_days=1000,
        )
    except CertificateError as exc:
        print("Expected issuance failure:", exc)

    try:
        pki.revoke_certificate(
            client.certificate_id,
            RevocationReason.KEY_COMPROMISE,
        )
    except CertificateError as exc:
        print("Expected revocation failure:", exc)

    assert pki.validate_certificate(root.certificate_id)[0]
    assert pki.validate_certificate(renewed.certificate_id)[0]
    assert not pki.validate_certificate(client.certificate_id)[0]

    print("\nAll PKI lifecycle assertions passed.")


if __name__ == "__main__":
    demonstrate_pki()
