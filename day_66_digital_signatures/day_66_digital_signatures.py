#!/usr/bin/env python3
"""
Digital Signatures: Signing, Verification, Certificates, and Trust.

Dependency:
    pip install cryptography

Uses Ed25519 for digital signatures and SHA-256 for certificate fingerprints.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys
import unittest

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:
    print("Install dependency: pip install cryptography", file=sys.stderr)
    raise SystemExit(1)


class SignatureStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    UNTRUSTED = "untrusted"
    REVOKED = "revoked"


class CertificateError(Exception):
    pass


class SignatureError(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fingerprint(public_key: Ed25519PublicKey) -> str:
    """Calculate a stable SHA-256 fingerprint of a public key."""
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class Certificate:
    subject: str
    issuer: str
    public_key: Ed25519PublicKey
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature: bytes = b""
    revoked: bool = False

    def certificate_payload(self) -> bytes:
        """Canonical representation of certificate fields."""
        data = {
            "subject": self.subject,
            "issuer": self.issuer,
            "public_key": self.public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ).hex(),
            "serial_number": self.serial_number,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
        }
        return json.dumps(
            data, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def is_time_valid(self, current_time: datetime) -> bool:
        return self.not_before <= current_time <= self.not_after


@dataclass
class TrustStore:
    """Stores trusted issuer public keys and certificate revocations."""

    trusted_issuers: dict[str, Ed25519PublicKey] = field(
        default_factory=dict
    )
    revoked_serials: set[str] = field(default_factory=set)

    def add_trusted_issuer(
        self, name: str, public_key: Ed25519PublicKey
    ) -> None:
        if not name:
            raise ValueError("Issuer name cannot be empty")
        self.trusted_issuers[name] = public_key

    def revoke(self, serial_number: str) -> None:
        self.revoked_serials.add(serial_number)

    def is_trusted(self, certificate: Certificate) -> bool:
        issuer_key = self.trusted_issuers.get(certificate.issuer)

        if issuer_key is None:
            return False

        try:
            issuer_key.verify(
                certificate.signature,
                certificate.certificate_payload(),
            )
            return True
        except InvalidSignature:
            return False


class CertificateAuthority:
    """Simplified certificate authority for a single issuing level."""

    def __init__(self, name: str):
        if not name:
            raise ValueError("CA name cannot be empty")

        self.name = name
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def issue_certificate(
        self,
        subject: str,
        public_key: Ed25519PublicKey,
        validity_days: int = 365,
    ) -> Certificate:
        if not subject:
            raise ValueError("Certificate subject cannot be empty")

        if validity_days <= 0:
            raise ValueError("Validity must be positive")

        current_time = utc_now()

        certificate = Certificate(
            subject=subject,
            issuer=self.name,
            public_key=public_key,
            serial_number=secrets.token_hex(16),
            not_before=current_time,
            not_after=current_time + timedelta(days=validity_days),
        )

        certificate.signature = self.private_key.sign(
            certificate.certificate_payload()
        )

        return certificate


class DigitalSigner:
    """Creates and verifies Ed25519 digital signatures."""

    def __init__(self, identity: str):
        if not identity:
            raise ValueError("Identity cannot be empty")

        self.identity = identity
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def sign(self, document: bytes) -> bytes:
        if not isinstance(document, bytes):
            raise TypeError("Document must be bytes")

        if not document:
            raise ValueError("Empty documents are not permitted")

        return self.private_key.sign(document)

    @staticmethod
    def verify(
        document: bytes,
        signature: bytes,
        public_key: Ed25519PublicKey,
    ) -> bool:
        try:
            public_key.verify(signature, document)
            return True
        except InvalidSignature:
            return False

    def export_public_key(self) -> str:
        encoded = self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return encoded.decode("ascii")


@dataclass
class SignedDocument:
    document_id: str
    document: bytes
    signature: bytes
    signer: str
    certificate: Certificate
    created_at: datetime
    document_hash: str


class SignatureService:
    """Coordinates signing, certificate validation, and verification."""

    def __init__(self, trust_store: TrustStore):
        self.trust_store = trust_store

    def sign_document(
        self,
        document_id: str,
        document: bytes,
        signer: DigitalSigner,
        certificate: Certificate,
    ) -> SignedDocument:

        if not document_id or not document:
            raise ValueError("Document ID and content are required")

        if certificate.subject != signer.identity:
            raise CertificateError("Signer identity mismatch")

        if fingerprint(certificate.public_key) != fingerprint(
            signer.public_key
        ):
            raise CertificateError("Certificate key mismatch")

        signature = signer.sign(document)

        return SignedDocument(
            document_id=document_id,
            document=document,
            signature=signature,
            signer=signer.identity,
            certificate=certificate,
            created_at=utc_now(),
            document_hash=hashlib.sha256(document).hexdigest(),
        )

    def verify_document(
        self,
        signed_document: SignedDocument,
        current_time: Optional[datetime] = None,
    ) -> SignatureStatus:

        current_time = current_time or utc_now()
        certificate = signed_document.certificate

        if certificate.serial_number in self.trust_store.revoked_serials:
            return SignatureStatus.REVOKED

        if certificate.revoked:
            return SignatureStatus.REVOKED

        if not certificate.is_time_valid(current_time):
            return SignatureStatus.EXPIRED

        if not self.trust_store.is_trusted(certificate):
            return SignatureStatus.UNTRUSTED

        if certificate.subject != signed_document.signer:
            return SignatureStatus.INVALID

        if fingerprint(certificate.public_key) != fingerprint(
            certificate.public_key
        ):
            return SignatureStatus.INVALID

        actual_hash = hashlib.sha256(
            signed_document.document
        ).hexdigest()

        if actual_hash != signed_document.document_hash:
            return SignatureStatus.INVALID

        if not DigitalSigner.verify(
            signed_document.document,
            signed_document.signature,
            certificate.public_key,
        ):
            return SignatureStatus.INVALID

        return SignatureStatus.VALID


def demonstrate() -> None:
    print("=" * 65)
    print("DIGITAL SIGNATURE DEMONSTRATION")
    print("=" * 65)

    # 1. Generate a certificate authority.
    ca = CertificateAuthority("Example Root CA")

    # 2. Configure the trust store.
    trust_store = TrustStore()
    trust_store.add_trusted_issuer(ca.name, ca.public_key)

    # 3. Generate the document signer's key pair.
    alice = DigitalSigner("alice@example.com")

    # 4. Issue a certificate binding Alice's identity to her public key.
    certificate = ca.issue_certificate(
        subject=alice.identity,
        public_key=alice.public_key,
        validity_days=365,
    )

    # 5. Sign a document.
    service = SignatureService(trust_store)
    original_document = (
        b"Enterprise agreement: payment due within 30 days."
    )

    signed = service.sign_document(
        document_id="DOC-2026-001",
        document=original_document,
        signer=alice,
        certificate=certificate,
    )

    print("\nDocument ID:", signed.document_id)
    print("Signer:", signed.signer)
    print("SHA-256:", signed.document_hash)
    print("Signature:", signed.signature.hex()[:48] + "...")
    print("Certificate serial:", certificate.serial_number)

    # 6. Verify signature and certificate trust.
    result = service.verify_document(signed)
    print("\nOriginal verification:", result.value)
    assert result == SignatureStatus.VALID

    # 7. Detect document tampering.
    tampered = SignedDocument(
        document_id=signed.document_id,
        document=b"Enterprise agreement: payment due within 90 days.",
        signature=signed.signature,
        signer=signed.signer,
        certificate=signed.certificate,
        created_at=signed.created_at,
        document_hash=signed.document_hash,
    )

    print(
        "Tampered document:",
        service.verify_document(tampered).value,
    )
    assert service.verify_document(tampered) == SignatureStatus.INVALID

    # 8. Detect revoked certificates.
    trust_store.revoke(certificate.serial_number)

    print(
        "Revoked certificate:",
        service.verify_document(signed).value,
    )
    assert service.verify_document(signed) == SignatureStatus.REVOKED

    # 9. Detect untrusted issuers.
    untrusted_store = TrustStore()
    untrusted_service = SignatureService(untrusted_store)

    print(
        "Unknown issuer:",
        untrusted_service.verify_document(
            SignedDocument(
                document_id=signed.document_id,
                document=signed.document,
                signature=signed.signature,
                signer=signed.signer,
                certificate=signed.certificate,
                created_at=signed.created_at,
                document_hash=signed.document_hash,
            )
        ).value,
    )

    print("\nDemonstration completed.")


class DigitalSignatureTests(unittest.TestCase):

    def setUp(self):
        self.ca = CertificateAuthority("Test CA")
        self.signer = DigitalSigner("tester@example.com")
        self.certificate = self.ca.issue_certificate(
            self.signer.identity,
            self.signer.public_key,
        )
        self.store = TrustStore()
        self.store.add_trusted_issuer(
            self.ca.name, self.ca.public_key
        )
        self.service = SignatureService(self.store)
        self.signed = self.service.sign_document(
            "TEST-001",
            b"Test document",
            self.signer,
            self.certificate,
        )

    def test_valid_signature(self):
        self.assertEqual(
            self.service.verify_document(self.signed),
            SignatureStatus.VALID,
        )

    def test_modified_document(self):
        self.signed.document = b"Modified content"
        self.assertEqual(
            self.service.verify_document(self.signed),
            SignatureStatus.INVALID,
        )

    def test_revoked_certificate(self):
        self.store.revoke(self.certificate.serial_number)
        self.assertEqual(
            self.service.verify_document(self.signed),
            SignatureStatus.REVOKED,
        )

    def test_untrusted_issuer(self):
        self.service = SignatureService(TrustStore())
        self.assertEqual(
            self.service.verify_document(self.signed),
            SignatureStatus.UNTRUSTED,
        )

    def test_expired_certificate(self):
        future = self.certificate.not_after + timedelta(seconds=1)
        self.assertEqual(
            self.service.verify_document(
                self.signed, current_time=future
            ),
            SignatureStatus.EXPIRED,
        )

    def test_wrong_document_signature(self):
        self.assertFalse(
            DigitalSigner.verify(
                b"Different content",
                self.signed.signature,
                self.signer.public_key,
            )
        )


if __name__ == "__main__":
    demonstrate()
    print("\nRunning automated tests...")
    unittest.main(argv=["digital_signatures.py"], exit=False)
