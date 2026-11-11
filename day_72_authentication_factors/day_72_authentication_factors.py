#!/usr/bin/env python3
"""
Authentication Factors: Passwords, MFA, Hardware Tokens,
Biometrics, and Adaptive Authentication.

Self-contained authentication policy and workflow simulator.
Python 3.10+
Standard-library dependencies only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import unittest
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class FactorType(str, Enum):
    PASSWORD = "password"
    TOTP = "totp"
    HARDWARE_TOKEN = "hardware_token"
    BIOMETRIC = "biometric"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthStatus(str, Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    MFA_REQUIRED = "mfa_required"
    STEP_UP_REQUIRED = "step_up_required"
    LOCKED = "locked"


@dataclass
class PasswordCredential:
    salt: str
    password_hash: str
    algorithm: str = "scrypt"
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class User:
    user_id: str
    username: str
    password: PasswordCredential
    enabled_factors: set[FactorType] = field(default_factory=set)
    totp_secret: Optional[str] = None
    hardware_secret: Optional[str] = None
    biometric_registered: bool = False
    failed_attempts: int = 0
    last_login: Optional[float] = None


@dataclass
class LoginContext:
    ip_address: str
    device_id: str
    country: str
    new_device: bool = False
    impossible_travel: bool = False
    sensitive_action: bool = False
    unusual_time: bool = False


@dataclass
class AuthResult:
    status: AuthStatus
    message: str
    risk: RiskLevel
    required_factors: list[str]
    completed_factors: list[str]


class AuthenticationError(Exception):
    pass


class PasswordService:
    """Uses salted scrypt password hashing and constant-time comparison."""

    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> PasswordCredential:
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters.")

        if len(password) > 1024:
            raise ValueError("Password exceeds the maximum supported length.")

        salt = salt or secrets.token_bytes(16)

        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )

        return PasswordCredential(
            salt=salt.hex(),
            password_hash=digest.hex(),
        )

    @staticmethod
    def verify(password: str, credential: PasswordCredential) -> bool:
        if credential.algorithm != "scrypt":
            raise AuthenticationError("Unsupported password hashing algorithm.")

        salt = bytes.fromhex(credential.salt)

        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )

        return hmac.compare_digest(
            candidate.hex(),
            credential.password_hash,
        )


class TOTPService:
    """RFC 6238-style six-digit TOTP using HMAC-SHA1."""

    @staticmethod
    def generate_secret() -> str:
        return secrets.token_hex(20)

    @staticmethod
    def generate_code(secret: str, timestamp: Optional[int] = None) -> str:
        timestamp = int(timestamp if timestamp is not None else time.time())
        counter = timestamp // 30

        key = bytes.fromhex(secret)
        message = counter.to_bytes(8, "big")

        digest = hmac.new(key, message, hashlib.sha1).digest()

        offset = digest[-1] & 0x0F

        number = (
            int.from_bytes(digest[offset:offset + 4], "big")
            & 0x7FFFFFFF
        )

        return f"{number % 1_000_000:06d}"

    @classmethod
    def verify(
        cls,
        secret: str,
        submitted_code: str,
        timestamp: Optional[int] = None,
        window: int = 1,
    ) -> bool:
        if not submitted_code.isdigit() or len(submitted_code) != 6:
            return False

        current = int(timestamp if timestamp is not None else time.time())

        # Accept a limited clock-skew window.
        for offset in range(-window, window + 1):
            expected = cls.generate_code(secret, current + offset * 30)

            if hmac.compare_digest(expected, submitted_code):
                return True

        return False


class HardwareTokenService:
    """
    Demonstration challenge-response verifier.

    HMAC models possession of a registered token secret.
    Production systems should use WebAuthn/FIDO2 public-key
    verification, origin checks, RP-ID checks and signature counters.
    """

    @staticmethod
    def create_challenge() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def create_demo_assertion(secret: str, challenge: str) -> str:
        return hmac.new(
            bytes.fromhex(secret),
            challenge.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def verify(
        secret: str,
        challenge: str,
        assertion: str,
    ) -> bool:
        expected = HardwareTokenService.create_demo_assertion(
            secret,
            challenge,
        )

        return hmac.compare_digest(expected, assertion)


class BiometricService:
    """
    Consumes a trusted operating-system biometric verification result.

    Raw fingerprints, face images and biometric templates are never
    collected or stored by this application.
    """

    @staticmethod
    def verify(
        platform_verified: bool,
        user_present: bool,
        trusted_platform: bool,
    ) -> bool:
        return (
            platform_verified is True
            and user_present is True
            and trusted_platform is True
        )


class AdaptiveRiskEngine:
    WEIGHTS = {
        "new_device": 25,
        "impossible_travel": 55,
        "unusual_time": 15,
        "sensitive_action": 20,
    }

    @classmethod
    def calculate(cls, context: LoginContext) -> tuple[int, RiskLevel]:
        score = sum(
            weight
            for name, weight in cls.WEIGHTS.items()
            if getattr(context, name)
        )

        if score >= 70:
            level = RiskLevel.CRITICAL
        elif score >= 45:
            level = RiskLevel.HIGH
        elif score >= 20:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return score, level


class AuthenticationEngine:
    MAX_FAILURES = 5
    LOCK_SECONDS = 300

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.audit_events: list[dict] = {}
        self.audit_events = []

    def register_user(
        self,
        username: str,
        password: str,
        factors: Optional[set[FactorType]] = None,
    ) -> User:
        if not username or len(username) > 100:
            raise ValueError("Invalid username.")

        if username in self.users:
            raise ValueError("Username already exists.")

        if factors is None:
            factors = {FactorType.PASSWORD, FactorType.TOTP}

        if FactorType.PASSWORD not in factors:
            raise ValueError("Password must be enabled for this demonstration.")

        user = User(
            user_id=secrets.token_hex(8),
            username=username,
            password=PasswordService.hash_password(password),
            enabled_factors=set(factors),
        )

        if FactorType.TOTP in factors:
            user.totp_secret = TOTPService.generate_secret()

        if FactorType.HARDWARE_TOKEN in factors:
            user.hardware_secret = secrets.token_bytes(32).hex()

        if FactorType.BIOMETRIC in factors:
            user.biometric_registered = True

        self.users[username] = user
        return user

    def _audit(self, username: str, event: str, details: dict) -> None:
        # Do not record passwords, TOTP codes, secrets or assertions.
        self.audit_events.append({
            "timestamp": int(time.time()),
            "username": username,
            "event": event,
            "details": details,
        })

    def authenticate(
        self,
        username: str,
        password: str,
        context: LoginContext,
        submitted_factors: Optional[dict] = None,
    ) -> AuthResult:

        submitted_factors = submitted_factors or {}

        user = self.users.get(username)

        if user is None:
            self._audit(username, "unknown_user", {})
            return AuthResult(
                AuthStatus.REJECTED,
                "Invalid credentials.",
                RiskLevel.LOW,
                [],
                [],
            )

        now = time.time()

        if now < user.password.locked_until:
            return AuthResult(
                AuthStatus.LOCKED,
                "Account temporarily locked.",
                RiskLevel.HIGH,
                [],
                [],
            )

        try:
            password_valid = PasswordService.verify(
                password,
                user.password,
            )
        except (ValueError, AuthenticationError):
            password_valid = False

        if not password_valid:
            user.password.failures += 1
            user.failed_attempts += 1

            if user.password.failures >= self.MAX_FAILURES:
                user.password.locked_until = now + self.LOCK_SECONDS

            self._audit(username, "password_failure", {
                "failure_count": user.password.failures,
            })

            return AuthResult(
                AuthStatus.LOCKED
                if user.password.locked_until > now
                else AuthStatus.REJECTED,
                "Invalid credentials.",
                RiskLevel.MEDIUM,
                [],
                [],
            )

        user.password.failures = 0

        score, risk = AdaptiveRiskEngine.calculate(context)

        required = [FactorType.PASSWORD.value]

        if FactorType.TOTP in user.enabled_factors:
            required.append(FactorType.TOTP.value)

        if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            if FactorType.HARDWARE_TOKEN in user.enabled_factors:
                required.append(FactorType.HARDWARE_TOKEN.value)
            elif FactorType.BIOMETRIC in user.enabled_factors:
                required.append(FactorType.BIOMETRIC.value)

        if context.sensitive_action and FactorType.BIOMETRIC in user.enabled_factors:
            if FactorType.BIOMETRIC.value not in required:
                required.append(FactorType.BIOMETRIC.value)

        completed = [FactorType.PASSWORD.value]

        if FactorType.TOTP.value in required:
            code = str(submitted_factors.get("totp", ""))

            if (
                user.totp_secret is None
                or not TOTPService.verify(user.totp_secret, code)
            ):
                self._audit(username, "totp_failure", {"risk_score": score})

                return AuthResult(
                    AuthStatus.MFA_REQUIRED,
                    "Valid TOTP verification is required.",
                    risk,
                    required,
                    completed,
                )

            completed.append(FactorType.TOTP.value)

        if FactorType.HARDWARE_TOKEN.value in required:
            challenge = str(submitted_factors.get("challenge", ""))
            assertion = str(submitted_factors.get("assertion", ""))

            if (
                not challenge
                or not assertion
                or user.hardware_secret is None
                or not HardwareTokenService.verify(
                    user.hardware_secret,
                    challenge,
                    assertion,
                )
            ):
                return AuthResult(
                    AuthStatus.STEP_UP_REQUIRED,
                    "Hardware-token verification failed.",
                    risk,
                    required,
                    completed,
                )

            completed.append(FactorType.HARDWARE_TOKEN.value)

        if FactorType.BIOMETRIC.value in required:
            biometric = submitted_factors.get("biometric", {})

            if not BiometricService.verify(
                biometric.get("verified") is True,
                biometric.get("user_present") is True,
                biometric.get("trusted_platform") is True,
            ):
                return AuthResult(
                    AuthStatus.STEP_UP_REQUIRED,
                    "Trusted biometric verification is required.",
                    risk,
                    required,
                    completed,
                )

            completed.append(FactorType.BIOMETRIC.value)

        user.last_login = now
        user.failed_attempts = 0

        self._audit(username, "authentication_success", {
            "risk_score": score,
            "risk_level": risk.value,
            "factors": completed,
        })

        return AuthResult(
            AuthStatus.SUCCESS,
            "Authentication successful.",
            risk,
            required,
            completed,
        )

    def export_audit(self, path: str) -> None:
        destination = Path(path)

        # Prevent accidental directory traversal through the filename.
        if destination.name != path or destination.name in {"", ".", ".."}:
            raise ValueError("Only a local filename is permitted.")

        destination.write_text(
            json.dumps(self.audit_events, indent=2),
            encoding="utf-8",
        )


class AuthenticationTests(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = AuthenticationEngine()
        self.user = self.engine.register_user(
            "engineer@example.com",
            "StrongPassword!2026",
            {
                FactorType.PASSWORD,
                FactorType.TOTP,
                FactorType.HARDWARE_TOKEN,
                FactorType.BIOMETRIC,
            },
        )

        self.context = LoginContext(
            ip_address="192.0.2.10",
            device_id="device-001",
            country="IN",
        )

    def test_password_hashing(self) -> None:
        self.assertTrue(
            PasswordService.verify(
                "StrongPassword!2026",
                self.user.password,
            )
        )

        self.assertFalse(
            PasswordService.verify("IncorrectPassword", self.user.password)
        )

    def test_totp(self) -> None:
        code = TOTPService.generate_code(
            self.user.totp_secret,
            1_800_000_000,
        )

        self.assertTrue(
            TOTPService.verify(
                self.user.totp_secret,
                code,
                1_800_000_000,
            )
        )

        self.assertFalse(
            TOTPService.verify(
                self.user.totp_secret,
                "000000",
                1_800_000_000,
            )
            and code != "000000"
        )

    def test_hardware_token(self) -> None:
        challenge = HardwareTokenService.create_challenge()

        assertion = HardwareTokenService.create_demo_assertion(
            self.user.hardware_secret,
            challenge,
        )

        self.assertTrue(
            HardwareTokenService.verify(
                self.user.hardware_secret,
                challenge,
                assertion,
            )
        )

    def test_biometric_attestation(self) -> None:
        self.assertTrue(BiometricService.verify(True, True, True))
        self.assertFalse(BiometricService.verify(True, False, True))
        self.assertFalse(BiometricService.verify(True, True, False))

    def test_risk_evaluation(self) -> None:
        score, risk = AdaptiveRiskEngine.calculate(
            LoginContext(
                "192.0.2.10",
                "unknown",
                "IN",
                new_device=True,
                impossible_travel=True,
            )
        )

        self.assertEqual(score, 80)
        self.assertEqual(risk, RiskLevel.CRITICAL)

    def test_successful_login(self) -> None:
        code = TOTPService.generate_code(self.user.totp_secret)

        result = self.engine.authenticate(
            self.user.username,
            "StrongPassword!2026",
            self.context,
            {"totp": code},
        )

        self.assertEqual(result.status, AuthStatus.SUCCESS)

    def test_invalid_password(self) -> None:
        result = self.engine.authenticate(
            self.user.username,
            "WrongPassword!2026",
            self.context,
        )

        self.assertEqual(result.status, AuthStatus.REJECTED)

    def test_adaptive_step_up(self) -> None:
        context = LoginContext(
            "198.51.100.5",
            "unknown-device",
            "US",
            new_device=True,
            impossible_travel=True,
        )

        result = self.engine.authenticate(
            self.user.username,
            "StrongPassword!2026",
            context,
            {},
        )

        self.assertEqual(result.status, AuthStatus.MFA_REQUIRED)

    def test_missing_biometric(self) -> None:
        context = LoginContext(
            "192.0.2.10",
            "device-001",
            "IN",
            sensitive_action=True,
        )

        code = TOTPService.generate_code(self.user.totp_secret)

        result = self.engine.authenticate(
            self.user.username,
            "StrongPassword!2026",
            context,
            {"totp": code},
        )

        self.assertEqual(result.status, AuthStatus.STEP_UP_REQUIRED)


def demonstration() -> None:
    engine = AuthenticationEngine()

    user = engine.register_user(
        "admin@example.com",
        "EnterprisePassword!2026",
        {
            FactorType.PASSWORD,
            FactorType.TOTP,
            FactorType.HARDWARE_TOKEN,
            FactorType.BIOMETRIC,
        },
    )

    context = LoginContext(
        ip_address="192.0.2.25",
        device_id="workstation-001",
        country="IN",
        new_device=True,
    )

    code = TOTPService.generate_code(user.totp_secret)

    result = engine.authenticate(
        user.username,
        "EnterprisePassword!2026",
        context,
        {"totp": code},
    )

    print("\nAUTHENTICATION RESULT")
    print(json.dumps({
        "status": result.status.value,
        "message": result.message,
        "risk": result.risk.value,
        "required_factors": result.required_factors,
        "completed_factors": result.completed_factors,
    }, indent=2))

    print("\nAUDIT EVENTS")
    print(json.dumps(engine.audit_events, indent=2))

    print("\nRunning tests...")
    unittest.main(argv=["authentication_factors.py"], exit=False)


if __name__ == "__main__":
    demonstration()
