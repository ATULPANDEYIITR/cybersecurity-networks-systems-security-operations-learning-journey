from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Iterable
import hashlib
import json
import logging
import re


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


class PatchStatus(Enum):
    PLANNED = "planned"
    DEPLOYING = "deploying"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class PatchError(Exception):
    """Base exception for patch-management failures."""


class ValidationError(PatchError):
    pass


class DeploymentError(PatchError):
    pass


@dataclass(frozen=True)
class Patch:
    patch_id: str
    title: str
    component: str
    version_before: str
    version_after: str
    severity: Severity
    release_date: date
    requires_reboot: bool
    checksum: str

    def validate(self) -> None:
        if not re.fullmatch(r"P-\d{4,}", self.patch_id):
            raise ValidationError(f"Invalid patch identifier: {self.patch_id}")
        if not self.title.strip() or not self.component.strip():
            raise ValidationError("Patch title and component are required.")
        if self.version_before == self.version_after:
            raise ValidationError("Patch must change the component version.")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", self.version_before):
            raise ValidationError("Invalid pre-patch version.")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", self.version_after):
            raise ValidationError("Invalid post-patch version.")
        if len(self.checksum) != 64 or not re.fullmatch(r"[0-9a-f]{64}", self.checksum):
            raise ValidationError("Checksum must be a SHA-256 hexadecimal digest.")


@dataclass
class Server:
    server_id: str
    hostname: str
    environment: Environment
    component_versions: dict[str, str]
    online: bool = True
    last_patched: date | None = None
    reboot_required: bool = False


@dataclass
class PatchDeployment:
    patch: Patch
    server_id: str
    status: PatchStatus = PatchStatus.PLANNED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    validation_message: str = ""

    def transition(self, new_status: PatchStatus) -> None:
        allowed = {
            PatchStatus.PLANNED: {PatchStatus.DEPLOYING, PatchStatus.FAILED},
            PatchStatus.DEPLOYING: {PatchStatus.VALIDATING, PatchStatus.FAILED},
            PatchStatus.VALIDATING: {
                PatchStatus.COMPLETED,
                PatchStatus.FAILED,
                PatchStatus.ROLLED_BACK,
            },
            PatchStatus.FAILED: {PatchStatus.ROLLED_BACK},
            PatchStatus.COMPLETED: set(),
            PatchStatus.ROLLED_BACK: set(),
        }
        if new_status not in allowed[self.status]:
            raise DeploymentError(
                f"Invalid state transition {self.status.value} -> {new_status.value}"
            )
        self.status = new_status


@dataclass
class PatchWindow:
    start: datetime
    end: datetime
    environments: set[Environment]

    def accepts(self, environment: Environment, moment: datetime) -> bool:
        return (
            environment in self.environments
            and self.start <= moment <= self.end
        )


@dataclass
class PatchManager:
    patches: dict[str, Patch] = field(default_factory=dict)
    servers: dict[str, Server] = field(default_factory=dict)
    deployments: list[PatchDeployment] = field(default_factory=list)

    def register_patch(self, patch: Patch) -> None:
        patch.validate()
        if patch.patch_id in self.patches:
            raise ValidationError(f"Patch already exists: {patch.patch_id}")
        self.patches[patch.patch_id] = patch

    def register_server(self, server: Server) -> None:
        if server.server_id in self.servers:
            raise ValidationError(f"Server already exists: {server.server_id}")
        self.servers[server.server_id] = server

    def plan(
        self,
        patch_id: str,
        server_id: str,
        window: PatchWindow,
        now: datetime,
    ) -> PatchDeployment:
        if patch_id not in self.patches:
            raise ValidationError(f"Unknown patch: {patch_id}")
        if server_id not in self.servers:
            raise ValidationError(f"Unknown server: {server_id}")

        patch = self.patches[patch_id]
        server = self.servers[server_id]

        if not server.online:
            raise DeploymentError(f"{server.hostname} is offline.")
        if not window.accepts(server.environment, now):
            raise DeploymentError("Server is outside the approved patch window.")

        current_version = server.component_versions.get(patch.component)
        if current_version != patch.version_before:
            raise ValidationError(
                f"Version mismatch: expected {patch.version_before}, "
                f"found {current_version!r}."
            )

        if patch.severity == Severity.CRITICAL and server.environment == Environment.PRODUCTION:
            logging.warning(
                "Critical patch %s is being scheduled directly for production.",
                patch.patch_id,
            )

        deployment = PatchDeployment(patch=patch, server_id=server_id)
        self.deployments.append(deployment)
        return deployment

    def deploy(
        self,
        deployment: PatchDeployment,
        observed_checksum: str,
        validation_probe: callable,
    ) -> None:
        server = self.servers[deployment.server_id]
        patch = deployment.patch

        if observed_checksum != patch.checksum:
            deployment.transition(PatchStatus.FAILED)
            raise DeploymentError("Patch checksum verification failed.")

        deployment.transition(PatchStatus.DEPLOYING)
        deployment.started_at = datetime.now()

        try:
            server.component_versions[patch.component] = patch.version_after
            if patch.requires_reboot:
                server.reboot_required = True

            deployment.transition(PatchStatus.VALIDATING)

            if not validation_probe(server):
                deployment.validation_message = "Post-patch validation failed."
                deployment.transition(PatchStatus.FAILED)
                self.rollback(deployment)
                return

            server.last_patched = date.today()
            server.reboot_required = False
            deployment.validation_message = "Service and version validation passed."
            deployment.transition(PatchStatus.COMPLETED)
            deployment.completed_at = datetime.now()

        except Exception as exc:
            logging.exception("Deployment failed for %s.", patch.patch_id)
            if deployment.status not in {
                PatchStatus.FAILED,
                PatchStatus.ROLLED_BACK,
            }:
                deployment.transition(PatchStatus.FAILED)
            raise DeploymentError(str(exc)) from exc

    def rollback(self, deployment: PatchDeployment) -> None:
        server = self.servers[deployment.server_id]
        patch = deployment.patch

        if server.component_versions.get(patch.component) == patch.version_after:
            server.component_versions[patch.component] = patch.version_before
        server.reboot_required = False

        if deployment.status == PatchStatus.FAILED:
            deployment.transition(PatchStatus.ROLLED_BACK)
        deployment.validation_message += " Rollback completed."

    def emergency_candidates(self) -> list[Patch]:
        return sorted(
            (
                p for p in self.patches.values()
                if p.severity in {Severity.HIGH, Severity.CRITICAL}
            ),
            key=lambda p: (
                0 if p.severity == Severity.CRITICAL else 1,
                p.release_date,
            ),
        )

    def overdue_servers(self, max_age_days: int = 30) -> list[Server]:
        cutoff = date.today() - timedelta(days=max_age_days)
        return [
            server
            for server in self.servers.values()
            if server.last_patched is None or server.last_patched < cutoff
        ]

    def export_report(self, path: Path) -> None:
        data = {
            "patches": [
                {
                    "patch_id": p.patch_id,
                    "title": p.title,
                    "component": p.component,
                    "version_before": p.version_before,
                    "version_after": p.version_after,
                    "severity": p.severity.value,
                    "release_date": p.release_date.isoformat(),
                    "requires_reboot": p.requires_reboot,
                }
                for p in self.patches.values()
            ],
            "servers": [
                {
                    "server_id": s.server_id,
                    "hostname": s.hostname,
                    "environment": s.environment.value,
                    "component_versions": s.component_versions,
                    "last_patched": (
                        s.last_patched.isoformat()
                        if s.last_patched else None
                    ),
                    "reboot_required": s.reboot_required,
                }
                for s in self.servers.values()
            ],
            "deployments": [
                {
                    "patch_id": d.patch.patch_id,
                    "server_id": d.server_id,
                    "status": d.status.value,
                    "validation": d.validation_message,
                }
                for d in self.deployments
            ],
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def sha256_for_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def service_validation(server: Server) -> bool:
    """A deterministic stand-in for service, process and health checks."""
    return (
        server.online
        and all(
            isinstance(version, str) and bool(version)
            for version in server.component_versions.values()
        )
        and not server.reboot_required
    )


def build_demo_manager() -> PatchManager:
    manager = PatchManager()

    openssl_patch = Patch(
        patch_id="P-1001",
        title="OpenSSL security update",
        component="openssl",
        version_before="3.0.12",
        version_after="3.0.17",
        severity=Severity.CRITICAL,
        release_date=date.today(),
        requires_reboot=False,
        checksum=sha256_for_text("openssl-3.0.17-security"),
    )

    kernel_patch = Patch(
        patch_id="P-1002",
        title="Linux kernel security maintenance",
        component="linux-kernel",
        version_before="6.1.70",
        version_after="6.1.112",
        severity=Severity.HIGH,
        release_date=date.today(),
        requires_reboot=True,
        checksum=sha256_for_text("kernel-6.1.112-security"),
    )

    manager.register_patch(openssl_patch)
    manager.register_patch(kernel_patch)

    manager.register_server(
        Server(
            server_id="srv-001",
            hostname="api-prod-01",
            environment=Environment.PRODUCTION,
            component_versions={
                "openssl": "3.0.12",
                "linux-kernel": "6.1.70",
            },
        )
    )
    manager.register_server(
        Server(
            server_id="srv-002",
            hostname="api-stage-01",
            environment=Environment.STAGING,
            component_versions={
                "openssl": "3.0.12",
                "linux-kernel": "6.1.70",
            },
        )
    )
    return manager


def run_demo() -> None:
    manager = build_demo_manager()

    now = datetime.now()
    emergency_window = PatchWindow(
        start=now - timedelta(minutes=10),
        end=now + timedelta(hours=2),
        environments={Environment.STAGING, Environment.PRODUCTION},
    )

    deployment = manager.plan("P-1001", "srv-001", emergency_window, now)

    patch_checksum = manager.patches["P-1001"].checksum
    manager.deploy(deployment, patch_checksum, service_validation)

    assert deployment.status == PatchStatus.COMPLETED
    assert (
        manager.servers["srv-001"].component_versions["openssl"]
        == "3.0.17"
    )

    print("Emergency patch deployment:", deployment.status.value)
    print(
        "Production OpenSSL version:",
        manager.servers["srv-001"].component_versions["openssl"],
    )

    print("\nEmergency candidates:")
    for patch in manager.emergency_candidates():
        print(f"  {patch.patch_id}: {patch.title} [{patch.severity.value}]")

    print("\nOverdue servers:")
    for server in manager.overdue_servers():
        print(f"  {server.hostname}")

    output = Path("patch_management_report.json")
    manager.export_report(output)
    print(f"\nReport written to {output.resolve()}")

    try:
        bad_deployment = manager.plan(
            "P-1002",
            "srv-001",
            emergency_window,
            now,
        )
        manager.deploy(
            bad_deployment,
            observed_checksum="incorrect-checksum",
            validation_probe=service_validation,
        )
    except PatchError as exc:
        print("Expected failure:", exc)


if __name__ == "__main__":
    run_demo()
