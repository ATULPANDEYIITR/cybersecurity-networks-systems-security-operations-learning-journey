#!/usr/bin/env python3
"""
Cryptography Security Review
----------------------------
A self-contained cryptographic security assessment engine.

Covers:
- Weak and deprecated cryptographic algorithms
- Insecure cryptographic configurations
- Key exposure and lifecycle failures
- Certificate validation and expiration
- TLS configuration
- Cryptographic randomness
- Risk scoring and remediation tracking
- Audit logging and JSON report generation

Python 3.10+
Standard-library only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import unittest

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------
# Logging
# ---------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

logger = logging.getLogger("crypto_security_review")


# ---------------------------------------------------------
# Enumerations
# ---------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    REMEDIATED = "REMEDIATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FindingCategory(str, Enum):
    WEAK_ALGORITHM = "WEAK_ALGORITHM"
    KEY_MANAGEMENT = "KEY_MANAGEMENT"
    KEY_EXPOSURE = "KEY_EXPOSURE"
    CERTIFICATE = "CERTIFICATE"
    TLS = "TLS"
    RANDOMNESS = "RANDOMNESS"
    CONFIGURATION = "CONFIGURATION"


# ---------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------

class SecurityReviewError(Exception):
    """Base exception for assessment failures."""


class ValidationError(SecurityReviewError):
    """Raised when an assessment input is invalid."""


class PolicyViolation(SecurityReviewError):
    """Raised when a security policy is violated."""


# ---------------------------------------------------------
# Security policies
# ---------------------------------------------------------

@dataclass(frozen=True)
class CryptoPolicy:
    deprecated_hashes: frozenset[str] = frozenset({
        "MD5", "SHA1", "SHA-1"
    })

    weak_symmetric_algorithms: frozenset[str] = frozenset({
        "DES", "3DES", "RC4", "BLOWFISH"
    })

    approved_hashes: frozenset[str] = frozenset({
        "SHA256", "SHA384", "SHA512"
    })

    minimum_rsa_bits: int = 2048
    minimum_ec_bits: int = 256
    maximum_certificate_age_days: int = 397
    minimum_key_rotation_days: int = 365

    require_authenticated_encryption: bool = True
    require_secure_randomness: bool = True
    reject_tls_legacy_versions: bool = True

    required_tls_versions: frozenset[str] = frozenset({
        "TLS1.2", "TLS1.3"
    })


# ---------------------------------------------------------
# Cryptographic asset models
# ---------------------------------------------------------

@dataclass
class CryptoAsset:
    asset_id: str
    name: str
    algorithm: str
    purpose: str
    key_bits: Optional[int] = None
    mode: Optional[str] = None
    authenticated: Optional[bool] = None
    tls_version: Optional[str] = None
    randomness_source: Optional[str] = None

    def validate(self) -> None:
        if not self.asset_id.strip():
            raise ValidationError("Asset ID cannot be empty.")

        if not self.name.strip():
            raise ValidationError("Asset name cannot be empty.")

        if not self.algorithm.strip():
            raise ValidationError("Algorithm cannot be empty.")

        if self.key_bits is not None and self.key_bits <= 0:
            raise ValidationError("Key size must be positive.")


@dataclass
class KeyRecord:
    key_id: str
    algorithm: str
    key_bits: int
    created_at: datetime
    last_rotated_at: Optional[datetime]
    storage_location: str
    exportable: bool
    exposed: bool = False

    def validate(self) -> None:
        if not self.key_id.strip():
            raise ValidationError("Key identifier is required.")

        if self.key_bits <= 0:
            raise ValidationError("Key size must be positive.")

        if self.created_at.tzinfo is None:
            raise ValidationError("Key creation time must be timezone-aware.")

        if self.last_rotated_at is not None:
            if self.last_rotated_at.tzinfo is None:
                raise ValidationError("Rotation time must be timezone-aware.")

            if self.last_rotated_at < self.created_at:
                raise ValidationError("Rotation cannot precede key creation.")


@dataclass
class CertificateRecord:
    certificate_id: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    hostname: str
    signature_algorithm: str
    public_key_algorithm: str
    public_key_bits: int
    trusted_issuer: bool
    revoked: bool = False
    chain_valid: bool = True

    def validate(self) -> None:
        if not self.certificate_id.strip():
            raise ValidationError("Certificate identifier is required.")

        if self.not_before.tzinfo is None or self.not_after.tzinfo is None:
            raise ValidationError("Certificate dates must be timezone-aware.")

        if self.not_after <= self.not_before:
            raise ValidationError("Invalid certificate validity period.")

        if self.public_key_bits <= 0:
            raise ValidationError("Invalid certificate public key size.")


# ---------------------------------------------------------
# Findings
# ---------------------------------------------------------

@dataclass
class SecurityFinding:
    finding_id: str
    asset_id: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    recommendation: str
    detected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    status: FindingStatus = FindingStatus.OPEN
    evidence: dict[str, Any] = field(default_factory=dict)

    def transition(self, new_status: FindingStatus) -> None:
        allowed = {
            FindingStatus.OPEN: {
                FindingStatus.IN_REVIEW,
                FindingStatus.REMEDIATED,
                FindingStatus.ACCEPTED_RISK,
                FindingStatus.FALSE_POSITIVE
            },
            FindingStatus.IN_REVIEW: {
                FindingStatus.OPEN,
                FindingStatus.REMEDIATED,
                FindingStatus.ACCEPTED_RISK,
                FindingStatus.FALSE_POSITIVE
            },
            FindingStatus.ACCEPTED_RISK: {
                FindingStatus.OPEN,
                FindingStatus.IN_REVIEW,
                FindingStatus.REMEDIATED
            },
            FindingStatus.REMEDIATED: set(),
            FindingStatus.FALSE_POSITIVE: set()
        }

        if new_status not in allowed[self.status]:
            raise PolicyViolation(
                f"Invalid finding transition: {self.status} -> {new_status}"
            )

        self.status = new_status


# ---------------------------------------------------------
# Cryptographic algorithm assessment
# ---------------------------------------------------------

class AlgorithmAnalyzer:

    def __init__(self, policy: CryptoPolicy):
        self.policy = policy

    def analyze(self, asset: CryptoAsset) -> list[dict[str, Any]]:
        asset.validate()
        findings = []

        algorithm = asset.algorithm.upper().replace("_", "-")

        if algorithm in {"MD5", "SHA1", "SHA-1"}:
            findings.append({
                "category": FindingCategory.WEAK_ALGORITHM,
                "severity": Severity.HIGH,
                "title": f"Deprecated hash algorithm: {algorithm}",
                "description": (
                    "The algorithm is unsuitable for modern collision-"
                    "resistant security applications."
                ),
                "recommendation": (
                    "Replace with SHA-256 or a stronger approved hash."
                )
            })

        if algorithm in self.policy.weak_symmetric_algorithms:
            findings.append({
                "category": FindingCategory.WEAK_ALGORITHM,
                "severity": Severity.CRITICAL,
                "title": f"Weak encryption algorithm: {algorithm}",
                "description": (
                    "The configured encryption algorithm is deprecated "
                    "or unsuitable for current security requirements."
                ),
                "recommendation": (
                    "Migrate to AES-256-GCM or another approved "
                    "authenticated encryption construction."
                )
            })

        if algorithm in {"RSA", "RSA-PSS"}:
            if asset.key_bits is None:
                findings.append({
                    "category": FindingCategory.CONFIGURATION,
                    "severity": Severity.MEDIUM,
                    "title": "RSA key size not specified",
                    "description": "The RSA key strength cannot be verified.",
                    "recommendation": "Record and verify the RSA modulus size."
                })
            elif asset.key_bits < self.policy.minimum_rsa_bits:
                findings.append({
                    "category": FindingCategory.WEAK_ALGORITHM,
                    "severity": Severity.HIGH,
                    "title": "Insufficient RSA key size",
                    "description": (
                        f"Configured RSA size is {asset.key_bits} bits."
                    ),
                    "recommendation": (
                        "Use RSA keys of at least 2048 bits, "
                        "subject to the applicable security policy."
                    )
                })

        if algorithm in {"AES", "AES-128", "AES-256"}:
            if asset.mode and asset.mode.upper() in {
                "ECB", "CBC_WITHOUT_MAC"
            }:
                findings.append({
                    "category": FindingCategory.CONFIGURATION,
                    "severity": Severity.HIGH,
                    "title": "Unsafe AES mode configuration",
                    "description": (
                        f"The configured mode {asset.mode} does not "
                        "provide authenticated encryption."
                    ),
                    "recommendation": (
                        "Use an authenticated mode such as AES-GCM "
                        "with correct nonce management."
                    )
                })

            if (
                self.policy.require_authenticated_encryption
                and asset.authenticated is False
            ):
                findings.append({
                    "category": FindingCategory.CONFIGURATION,
                    "severity": Severity.HIGH,
                    "title": "Missing encryption authentication",
                    "description": (
                        "The encryption configuration does not "
                        "authenticate ciphertext."
                    ),
                    "recommendation": (
                        "Use authenticated encryption and verify "
                        "authentication tags before accepting plaintext."
                    )
                })

        if algorithm in {"AES-128", "AES"}:
            if asset.key_bits == 128:
                findings.append({
                    "category": FindingCategory.CONFIGURATION,
                    "severity": Severity.LOW,
                    "title": "AES-128 configuration",
                    "description": (
                        "AES-128 is not inherently broken. "
                        "Verify whether organizational policy requires "
                        "AES-256."
                    ),
                    "recommendation": (
                        "Confirm the required security strength and "
                        "applicable compliance policy."
                    )
                })

        if asset.tls_version:
            if asset.tls_version.upper() not in self.policy.required_tls_versions:
                findings.append({
                    "category": FindingCategory.TLS,
                    "severity": Severity.HIGH,
                    "title": "Unsupported TLS protocol version",
                    "description": (
                        f"Configured protocol: {asset.tls_version}"
                    ),
                    "recommendation": (
                        "Use TLS 1.2 or TLS 1.3 with secure cipher suites."
                    )
                })

        if (
            asset.randomness_source
            and asset.randomness_source.lower() in {
                "random.random", "math.random", "time", "static_seed"
            }
        ):
            findings.append({
                "category": FindingCategory.RANDOMNESS,
                "severity": Severity.CRITICAL,
                "title": "Insecure randomness source",
                "description": (
                    "A predictable randomness source is being used."
                ),
                "recommendation": (
                    "Use an operating-system cryptographically secure "
                    "random number generator."
                )
            })

        return findings


# ---------------------------------------------------------
# Key management assessment
# ---------------------------------------------------------

class KeyAnalyzer:

    def __init__(self, policy: CryptoPolicy):
        self.policy = policy

    def analyze(self, key: KeyRecord) -> list[dict[str, Any]]:
        key.validate()

        findings = []
        now = datetime.now(timezone.utc)

        if key.exposed:
            findings.append({
                "category": FindingCategory.KEY_EXPOSURE,
                "severity": Severity.CRITICAL,
                "title": "Cryptographic key exposure",
                "description": (
                    "The key is reported as exposed. It must be "
                    "treated as compromised."
                ),
                "recommendation": (
                    "Revoke dependent credentials, rotate the key, "
                    "investigate exposure, and assess historical usage."
                )
            })

        if key.exportable and key.storage_location.upper() != "HSM":
            findings.append({
                "category": FindingCategory.KEY_MANAGEMENT,
                "severity": Severity.HIGH,
                "title": "Exportable key outside hardware protection",
                "description": (
                    "The private or symmetric key is exportable and "
                    "is not recorded as protected by an HSM."
                ),
                "recommendation": (
                    "Use controlled key custody, non-exportable keys, "
                    "or an approved hardware security boundary."
                )
            })

        reference_date = key.last_rotated_at or key.created_at

        age = (now - reference_date).days

        if age > self.policy.minimum_key_rotation_days:
            findings.append({
                "category": FindingCategory.KEY_MANAGEMENT,
                "severity": Severity.MEDIUM,
                "title": "Key rotation overdue",
                "description": f"Key age since last rotation: {age} days.",
                "recommendation": (
                    "Rotate according to cryptoperiod, exposure risk, "
                    "key purpose, and organizational policy."
                )
            })

        if key.algorithm.upper() == "RSA" and key.key_bits < 2048:
            findings.append({
                "category": FindingCategory.WEAK_ALGORITHM,
                "severity": Severity.HIGH,
                "title": "Weak RSA key",
                "description": "RSA modulus is below 2048 bits.",
                "recommendation": "Replace with an appropriately sized key."
            })

        return findings


# ---------------------------------------------------------
# Certificate assessment
# ---------------------------------------------------------

class CertificateAnalyzer:

    def __init__(self, policy: CryptoPolicy):
        self.policy = policy

    @staticmethod
    def hostname_matches(pattern: str, hostname: str) -> bool:
        pattern = pattern.lower().rstrip(".")
        hostname = hostname.lower().rstrip(".")

        if pattern == hostname:
            return True

        if pattern.startswith("*."):
            suffix = pattern[2:]

            if not hostname.endswith("." + suffix):
                return False

            prefix = hostname[:-(len(suffix) + 1)]
            return bool(prefix) and "." not in prefix

        return False

    def analyze(
        self,
        certificate: CertificateRecord,
        expected_hostname: str
    ) -> list[dict[str, Any]]:

        certificate.validate()

        findings = []
        now = datetime.now(timezone.utc)

        if now < certificate.not_before:
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.HIGH,
                "title": "Certificate not yet valid",
                "description": "Current time precedes certificate validity.",
                "recommendation": "Verify system clocks and certificate dates."
            })

        if now >= certificate.not_after:
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.CRITICAL,
                "title": "Certificate expired",
                "description": "The certificate has passed its expiry date.",
                "recommendation": "Renew and deploy a valid certificate."
            })
        elif (certificate.not_after - now).days <= 30:
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.MEDIUM,
                "title": "Certificate approaching expiration",
                "description": "Certificate expires within 30 days.",
                "recommendation": "Schedule certificate renewal."
            })

        if certificate.revoked:
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.CRITICAL,
                "title": "Certificate revoked",
                "description": "Certificate revocation is reported.",
                "recommendation": "Reject the certificate and investigate."
            })

        if not certificate.trusted_issuer:
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.HIGH,
                "title": "Untrusted certificate issuer",
                "description": "Issuer is not in the trusted CA set.",
                "recommendation": (
                    "Validate the complete chain against trusted "
                    "trust anchors."
                )
            })

        if not certificate.chain_valid:
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.HIGH,
                "title": "Invalid certificate chain",
                "description": "Certificate chain validation failed.",
                "recommendation": (
                    "Inspect intermediate certificates, signatures, "
                    "constraints, and trust anchors."
                )
            })

        if not self.hostname_matches(
            certificate.hostname,
            expected_hostname
        ):
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.HIGH,
                "title": "Hostname mismatch",
                "description": (
                    f"Expected {expected_hostname}; "
                    f"certificate identity is {certificate.hostname}."
                ),
                "recommendation": (
                    "Issue or deploy a certificate containing the "
                    "correct hostname in its Subject Alternative Name."
                )
            })

        if certificate.signature_algorithm.upper() in {
            "MD5", "SHA1", "SHA-1", "MD5WITHRSA", "SHA1WITHRSA"
        }:
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.HIGH,
                "title": "Weak certificate signature algorithm",
                "description": (
                    "Certificate signature uses a deprecated hash."
                ),
                "recommendation": (
                    "Replace with a certificate signed using "
                    "a modern approved signature algorithm."
                )
            })

        if (
            certificate.public_key_algorithm.upper() == "RSA"
            and certificate.public_key_bits < self.policy.minimum_rsa_bits
        ):
            findings.append({
                "category": FindingCategory.CERTIFICATE,
                "severity": Severity.HIGH,
                "title": "Weak certificate public key",
                "description": "RSA certificate key is undersized.",
                "recommendation": "Replace with an adequately sized key."
            })

        return findings


# ---------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------

class RiskScorer:

    WEIGHTS = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 7,
        Severity.MEDIUM: 4,
        Severity.LOW: 2,
        Severity.INFORMATIONAL: 1
    }

    @classmethod
    def calculate(cls, findings: list[SecurityFinding]) -> int:
        score = sum(
            cls.WEIGHTS[f.severity]
            for f in findings
            if f.status == FindingStatus.OPEN
        )
        return min(score, 100)

    @classmethod
    def classify(cls, score: int) -> str:
        if score >= 30:
            return "CRITICAL"
        if score >= 18:
            return "HIGH"
        if score >= 8:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NO_OPEN_FINDINGS"


# ---------------------------------------------------------
# Assessment engine
# ---------------------------------------------------------

class CryptoSecurityReview:

    def __init__(self, policy: Optional[CryptoPolicy] = None):
        self.policy = policy or CryptoPolicy()

        self.algorithm_analyzer = AlgorithmAnalyzer(self.policy)
        self.key_analyzer = KeyAnalyzer(self.policy)
        self.certificate_analyzer = CertificateAnalyzer(self.policy)

        self.assets: dict[str, CryptoAsset] = {}
        self.findings: dict[str, SecurityFinding] = {}

        self._sequence = 0

    def _create_finding(
        self,
        asset_id: str,
        data: dict[str, Any]
    ) -> SecurityFinding:

        self._sequence += 1

        finding = SecurityFinding(
            finding_id=f"CRYPTO-{self._sequence:05d}",
            asset_id=asset_id,
            category=data["category"],
            severity=data["severity"],
            title=data["title"],
            description=data["description"],
            recommendation=data["recommendation"]
        )

        self.findings[finding.finding_id] = finding

        return finding

    def register_asset(self, asset: CryptoAsset) -> None:
        asset.validate()

        if asset.asset_id in self.assets:
            raise ValidationError("Duplicate asset identifier.")

        self.assets[asset.asset_id] = asset

    def assess_asset(self, asset_id: str) -> list[SecurityFinding]:
        if asset_id not in self.assets:
            raise ValidationError("Unknown cryptographic asset.")

        asset = self.assets[asset_id]

        data = self.algorithm_analyzer.analyze(asset)

        return [
            self._create_finding(asset_id, item)
            for item in data
        ]

    def assess_key(self, key: KeyRecord) -> list[SecurityFinding]:
        return [
            self._create_finding(key.key_id, item)
            for item in self.key_analyzer.analyze(key)
        ]

    def assess_certificate(
        self,
        certificate: CertificateRecord,
        expected_hostname: str
    ) -> list[SecurityFinding]:

        return [
            self._create_finding(certificate.certificate_id, item)
            for item in self.certificate_analyzer.analyze(
                certificate,
                expected_hostname
            )
        ]

    def get_finding(self, finding_id: str) -> SecurityFinding:
        try:
            return self.findings[finding_id]
        except KeyError as exc:
            raise ValidationError("Finding not found.") from exc

    def update_finding(
        self,
        finding_id: str,
        status: FindingStatus
    ) -> None:
        self.get_finding(finding_id).transition(status)

    def report(self) -> dict[str, Any]:
        findings = list(self.findings.values())

        severity_counts = Counter(
            finding.severity.value for finding in findings
        )

        status_counts = Counter(
            finding.status.value for finding in findings
        )

        score = RiskScorer.calculate(findings)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "asset_count": len(self.assets),
            "finding_count": len(findings),
            "risk_score": score,
            "risk_level": RiskScorer.classify(score),
            "severity_distribution": dict(severity_counts),
            "status_distribution": dict(status_counts),
            "findings": [
                {
                    **asdict(finding),
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "detected_at": finding.detected_at.isoformat()
                }
                for finding in findings
            ]
        }

    def export_json(self, path: str) -> None:
        destination = Path(path)

        # Restrict report output to a caller-selected file.
        # Evidence must never contain raw cryptographic key material.
        destination.write_text(
            json.dumps(self.report(), indent=2),
            encoding="utf-8"
        )


# ---------------------------------------------------------
# Demonstration
# ---------------------------------------------------------

def run_demo() -> CryptoSecurityReview:
    review = CryptoSecurityReview()

    assets = [
        CryptoAsset(
            "ASSET-001",
            "Legacy Authentication Service",
            "SHA1",
            "Password integrity"
        ),
        CryptoAsset(
            "ASSET-002",
            "Payment Encryption Service",
            "AES",
            "Payment encryption",
            key_bits=256,
            mode="ECB",
            authenticated=False
        ),
        CryptoAsset(
            "ASSET-003",
            "External API",
            "RSA",
            "Digital signatures",
            key_bits=1024,
            tls_version="TLS1.0"
        ),
        CryptoAsset(
            "ASSET-004",
            "Session Token Generator",
            "AES-256",
            "Token protection",
            key_bits=256,
            randomness_source="math.random"
        ),
        CryptoAsset(
            "ASSET-005",
            "Modern Storage Service",
            "AES-256",
            "Data encryption",
            key_bits=256,
            mode="GCM",
            authenticated=True,
            randomness_source="secrets"
        )
    ]

    for asset in assets:
        review.register_asset(asset)
        review.assess_asset(asset.asset_id)

    now = datetime.now(timezone.utc)

    keys = [
        KeyRecord(
            "KEY-001",
            "RSA",
            1024,
            now - timedelta(days=600),
            now - timedelta(days=500),
            "LOCAL_FILE",
            True,
            True
        ),
        KeyRecord(
            "KEY-002",
            "AES",
            256,
            now - timedelta(days=30),
            now - timedelta(days=15),
            "HSM",
            False
        )
    ]

    for key in keys:
        review.assess_key(key)

    certificate = CertificateRecord(
        certificate_id="CERT-001",
        subject="api.example.com",
        issuer="Unknown CA",
        not_before=now - timedelta(days=500),
        not_after=now - timedelta(days=5),
        hostname="old.example.com",
        signature_algorithm="SHA1WITHRSA",
        public_key_algorithm="RSA",
        public_key_bits=1024,
        trusted_issuer=False,
        revoked=True,
        chain_valid=False
    )

    review.assess_certificate(
        certificate,
        "api.example.com"
    )

    return review


# ---------------------------------------------------------
# Tests
# ---------------------------------------------------------

class SecurityReviewTests(unittest.TestCase):

    def test_weak_hash_detection(self):
        review = CryptoSecurityReview()

        asset = CryptoAsset(
            "A1", "Test", "MD5", "Integrity"
        )

        review.register_asset(asset)
        findings = review.assess_asset("A1")

        self.assertTrue(findings)
        self.assertEqual(
            findings[0].severity,
            Severity.HIGH
        )

    def test_duplicate_asset_rejected(self):
        review = CryptoSecurityReview()
        asset = CryptoAsset("A1", "Test", "SHA256", "Hash")

        review.register_asset(asset)

        with self.assertRaises(ValidationError):
            review.register_asset(asset)

    def test_finding_transition(self):
        review = CryptoSecurityReview()

        asset = CryptoAsset("A1", "Test", "MD5", "Hash")
        review.register_asset(asset)

        finding = review.assess_asset("A1")[0]

        finding.transition(FindingStatus.IN_REVIEW)
        finding.transition(FindingStatus.REMEDIATED)

        self.assertEqual(
            finding.status,
            FindingStatus.REMEDIATED
        )

    def test_terminal_finding_state(self):
        review = CryptoSecurityReview()
        asset = CryptoAsset("A1", "Test", "MD5", "Hash")

        review.register_asset(asset)
        finding = review.assess_asset("A1")[0]

        finding.transition(FindingStatus.REMEDIATED)

        with self.assertRaises(PolicyViolation):
            finding.transition(FindingStatus.OPEN)

    def test_secure_randomness_not_flagged(self):
        review = CryptoSecurityReview()

        asset = CryptoAsset(
            "A1",
            "Secure Service",
            "AES-256",
            "Encryption",
            key_bits=256,
            mode="GCM",
            authenticated=True,
            randomness_source="secrets"
        )

        review.register_asset(asset)

        findings = review.assess_asset("A1")

        self.assertFalse(any(
            f.category == FindingCategory.RANDOMNESS
            for f in findings
        ))

    def test_hostname_matching(self):
        analyzer = CertificateAnalyzer(CryptoPolicy())

        self.assertTrue(
            analyzer.hostname_matches(
                "*.example.com",
                "api.example.com"
            )
        )

        self.assertFalse(
            analyzer.hostname_matches(
                "*.example.com",
                "a.b.example.com"
            )
        )

    def test_risk_score(self):
        finding = SecurityFinding(
            "F1",
            "A1",
            FindingCategory.KEY_EXPOSURE,
            Severity.CRITICAL,
            "Exposure",
            "Key exposed",
            "Rotate key"
        )

        self.assertEqual(
            RiskScorer.calculate([finding]),
            10
        )


# ---------------------------------------------------------
# Entry point
# ---------------------------------------------------------

if __name__ == "__main__":
    review = run_demo()

    print("\nCRYPTOGRAPHY SECURITY REVIEW")
    print("=" * 55)

    report = review.report()

    print(json.dumps({
        "asset_count": report["asset_count"],
        "finding_count": report["finding_count"],
        "risk_score": report["risk_score"],
        "risk_level": report["risk_level"],
        "severity_distribution": report["severity_distribution"]
    }, indent=2))

    print("\nDETECTED FINDINGS")

    for finding in review.findings.values():
        print(
            f"[{finding.severity.value}] "
            f"{finding.finding_id}: {finding.title}"
        )

    print("\nRUNNING VALIDATION TESTS")

    unittest.main(argv=["crypto_review"], exit=False)
