#!/usr/bin/env python3
"""
Linux Services: systemd, daemons, service configuration, and startup services.

This self-contained program is a learning-oriented service-management simulator.
It models concepts that are normally handled by systemd on Linux while remaining
safe to execute on any operating system. It also includes optional inspection of
real Linux service files when the script is actually running on Linux.

The simulator deliberately distinguishes:
- systemd's unit/service lifecycle
- daemon behavior
- service configuration
- startup/boot enablement
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import os
import platform
import shlex
import signal
import subprocess
import tempfile
import textwrap
import time
from typing import Dict, List, Optional, Sequence


class ServiceState(Enum):
    STOPPED = "inactive"
    STARTING = "activating"
    RUNNING = "active"
    STOPPING = "deactivating"
    FAILED = "failed"


class EnableState(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"
    STATIC = "static"


@dataclass
class ServiceConfig:
    name: str
    description: str
    command: List[str]
    working_directory: Optional[Path] = None
    environment: Dict[str, str] = field(default_factory=dict)
    restart_policy: str = "no"
    restart_sec: float = 1.0
    wanted_by: str = "multi-user.target"
    dependencies: List[str] = field(default_factory=list)
    user: Optional[str] = None

    def validate(self) -> None:
        if not self.name.endswith(".service"):
            raise ValueError("A service unit name must end with .service")
        if not self.command:
            raise ValueError("ExecStart requires at least one command")
        if self.restart_policy not in {"no", "on-failure", "always"}:
            raise ValueError("Unsupported restart policy")
        if self.restart_sec < 0:
            raise ValueError("restart_sec cannot be negative")
        if not self.wanted_by:
            raise ValueError("wanted_by cannot be empty")


@dataclass
class SimulatedService:
    config: ServiceConfig
    state: ServiceState = ServiceState.STOPPED
    enabled: EnableState = EnableState.DISABLED
    restart_count: int = 0
    last_error: Optional[str] = None
    logs: List[str] = field(default_factory=list)

    def log(self, message: str) -> None:
        entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {self.config.name}: {message}"
        self.logs.append(entry)

    def start(self, manager: "ServiceManager") -> bool:
        if self.state == ServiceState.RUNNING:
            self.log("start requested while already active")
            return True

        try:
            self.config.validate()
        except ValueError as exc:
            self.state = ServiceState.FAILED
            self.last_error = str(exc)
            self.log(f"configuration rejected: {exc}")
            return False

        for dependency in self.config.dependencies:
            dependency_service = manager.services.get(dependency)
            if dependency_service is None:
                self.state = ServiceState.FAILED
                self.last_error = f"missing dependency: {dependency}"
                self.log(self.last_error)
                return False

            if not dependency_service.start(manager):
                self.state = ServiceState.FAILED
                self.last_error = f"dependency failed: {dependency}"
                self.log(self.last_error)
                return False

        self.state = ServiceState.STARTING
        self.log("transitioning from inactive to activating")

        # A real systemd service would launch ExecStart and track its process.
        # The simulator models the successful activation transition explicitly.
        if self.config.command[0] == "FAIL":
            self.state = ServiceState.FAILED
            self.last_error = "simulated ExecStart failure"
            self.log(self.last_error)
            return False

        self.state = ServiceState.RUNNING
        self.last_error = None
        self.log("service entered active state")
        return True

    def stop(self) -> bool:
        if self.state == ServiceState.STOPPED:
            self.log("stop requested while already inactive")
            return True

        if self.state == ServiceState.FAILED:
            self.state = ServiceState.STOPPED
            self.log("failed service reset to inactive")
            return True

        self.state = ServiceState.STOPPING
        self.log("transitioning from active to deactivating")
        self.state = ServiceState.STOPPED
        self.log("service entered inactive state")
        return True

    def restart(self, manager: "ServiceManager") -> bool:
        self.log("restart requested")
        self.stop()
        self.restart_count += 1
        return self.start(manager)

    def enable(self) -> None:
        if not self.config.wanted_by:
            raise ValueError("Cannot enable service without a target")
        self.enabled = EnableState.ENABLED
        self.log(f"enabled for {self.config.wanted_by}")

    def disable(self) -> None:
        self.enabled = EnableState.DISABLED
        self.log("disabled from startup")

    def unit_text(self) -> str:
        """Produce a realistic systemd unit file representation."""
        lines = [
            "[Unit]",
            f"Description={self.config.description}",
        ]

        if self.config.dependencies:
            lines.append("After=" + " ".join(self.config.dependencies))

        lines.extend([
            "",
            "[Service]",
            "Type=simple",
            f"ExecStart={shlex.join(self.config.command)}",
            f"Restart={self.config.restart_policy}",
            f"RestartSec={self.config.restart_sec:g}",
        ])

        if self.config.working_directory:
            lines.append(f"WorkingDirectory={self.config.working_directory}")

        if self.config.user:
            lines.append(f"User={self.config.user}")

        for key, value in sorted(self.config.environment.items()):
            lines.append(f"Environment={key}={value}")

        lines.extend([
            "",
            "[Install]",
            f"WantedBy={self.config.wanted_by}",
        ])
        return "\n".join(lines)


class ServiceManager:
    """A small model of systemd's service-management responsibilities."""

    def __init__(self) -> None:
        self.services: Dict[str, SimulatedService] = {}

    def add(self, service: SimulatedService) -> None:
        name = service.config.name
        if name in self.services:
            raise ValueError(f"Service already exists: {name}")
        service.config.validate()
        self.services[name] = service

    def start(self, name: str) -> bool:
        service = self.require(name)
        return service.start(self)

    def stop(self, name: str) -> bool:
        return self.require(name).stop()

    def restart(self, name: str) -> bool:
        return self.require(name).restart(self)

    def enable(self, name: str) -> None:
        self.require(name).enable()

    def disable(self, name: str) -> None:
        self.require(name).disable()

    def status(self, name: str) -> str:
        service = self.require(name)
        lines = [
            f"● {service.config.name} - {service.config.description}",
            f"   Loaded: generated unit configuration",
            f"   Active: {service.state.value}",
            f"   Startup: {service.enabled.value}",
            f"   Restart count: {service.restart_count}",
        ]
        if service.last_error:
            lines.append(f"   Error: {service.last_error}")
        return "\n".join(lines)

    def require(self, name: str) -> SimulatedService:
        try:
            return self.services[name]
        except KeyError as exc:
            raise KeyError(f"Unknown service: {name}") from exc

    def boot(self) -> None:
        """Start enabled services in dependency-aware order."""
        print("\nSimulated boot sequence")
        for service in self.services.values():
            if service.enabled == EnableState.ENABLED:
                self.start(service.config.name)

    def list_units(self) -> None:
        for service in self.services.values():
            print(
                f"{service.config.name:28} "
                f"{service.state.value:12} "
                f"{service.enabled.value:10}"
            )


def demonstrate_unit_configuration() -> SimulatedService:
    config = ServiceConfig(
        name="inventory-worker.service",
        description="Inventory background processing daemon",
        command=["/opt/inventory/bin/worker", "--config", "/etc/inventory/worker.conf"],
        working_directory=Path("/opt/inventory"),
        environment={
            "APP_ENV": "production",
            "LOG_LEVEL": "info",
        },
        restart_policy="on-failure",
        restart_sec=5,
        dependencies=["network-online.target.service"],
        user="inventory",
    )

    service = SimulatedService(config)
    print("\nGenerated service configuration")
    print(service.unit_text())
    return service


def demonstrate_daemon_lifecycle(manager: ServiceManager) -> None:
    print("\nDaemon lifecycle")
    print(manager.status("inventory-worker.service"))

    print("\nStarting daemon")
    manager.start("inventory-worker.service")
    print(manager.status("inventory-worker.service"))

    print("\nRestarting daemon")
    manager.restart("inventory-worker.service")
    print(manager.status("inventory-worker.service"))

    print("\nStopping daemon")
    manager.stop("inventory-worker.service")
    print(manager.status("inventory-worker.service"))


def demonstrate_failure_handling() -> None:
    manager = ServiceManager()

    failing = SimulatedService(
        ServiceConfig(
            name="broken-worker.service",
            description="Demonstration of a failed daemon",
            command=["FAIL", "--config", "/etc/broken.conf"],
            restart_policy="on-failure",
        )
    )
    manager.add(failing)

    print("\nFailure handling")
    manager.start(failing.config.name)
    print(manager.status(failing.config.name))
    print("Recorded service log:")
    print(failing.logs[-1])


def demonstrate_startup_services() -> None:
    manager = ServiceManager()

    network = SimulatedService(
        ServiceConfig(
            name="network-online.target.service",
            description="Network availability target",
            command=["/bin/true"],
        )
    )
    network.enabled = EnableState.STATIC

    application = SimulatedService(
        ServiceConfig(
            name="billing-api.service",
            description="Billing API daemon",
            command=["/opt/billing/bin/server", "--port", "8080"],
            environment={"APP_ENV": "production"},
            restart_policy="always",
            restart_sec=3,
            dependencies=["network-online.target.service"],
            user="billing",
        )
    )

    manager.add(network)
    manager.add(application)
    manager.enable(application.config.name)

    print("\nStartup configuration before boot")
    manager.list_units()

    manager.boot()

    print("\nStartup configuration after boot")
    manager.list_units()


def demonstrate_validation() -> None:
    print("\nConfiguration validation")

    invalid_configs = [
        ServiceConfig(
            name="invalid-unit",
            description="Missing .service suffix",
            command=["/bin/true"],
        ),
        ServiceConfig(
            name="invalid-restart.service",
            description="Unsupported restart policy",
            command=["/bin/true"],
            restart_policy="sometimes",
        ),
        ServiceConfig(
            name="invalid-command.service",
            description="Missing ExecStart",
            command=[],
        ),
    ]

    for config in invalid_configs:
        try:
            config.validate()
        except ValueError as exc:
            print(f"Rejected {config.name}: {exc}")


def run_safe_linux_command(command: Sequence[str]) -> Optional[str]:
    """
    Execute only read-oriented Linux service commands.

    The function intentionally does not invoke systemctl start/stop/enable/disable.
    Service state changes can require root privileges and can affect the host.
    """
    if platform.system() != "Linux":
        return None

    allowed = {
        ("systemctl", "--version"),
        ("systemctl", "list-unit-files", "--type=service", "--no-pager"),
    }

    if tuple(command) not in allowed:
        raise ValueError("Command is not in the read-only allowlist")

    try:
        result = subprocess.run(
            list(command),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout
    except (subprocess.SubprocessError, OSError) as exc:
        return f"Linux command failed: {exc}"


def inspect_linux_environment() -> None:
    print("\nHost inspection")

    if platform.system() != "Linux":
        print("This host is not Linux; live systemd inspection is skipped.")
        return

    version = run_safe_linux_command(["systemctl", "--version"])
    if version:
        print(version.splitlines()[0])

    units = run_safe_linux_command(
        ["systemctl", "list-unit-files", "--type=service", "--no-pager"]
    )
    if units:
        print("\nFirst service-unit entries:")
        for line in units.splitlines()[:12]:
            print(line)


def demonstrate_unit_file_safety() -> None:
    """
    A service file is configuration, not an arbitrary shell script.

    Writing a candidate unit into a temporary directory is safe because the
    simulator never installs it into /etc/systemd/system or reloads systemd.
    """
    service = SimulatedService(
        ServiceConfig(
            name="reporting-daemon.service",
            description="Reporting daemon",
            command=["/usr/local/bin/reporting-daemon", "--config", "/etc/reporting.conf"],
            environment={"REPORT_INTERVAL": "60"},
            restart_policy="on-failure",
            restart_sec=10,
            wanted_by="multi-user.target",
        )
    )

    with tempfile.TemporaryDirectory(prefix="systemd-demo-") as directory:
        path = Path(directory) / service.config.name
        path.write_text(service.unit_text() + "\n", encoding="utf-8")
        print(f"\nSafe candidate unit written to: {path}")
        print(path.read_text(encoding="utf-8"))


def print_logs(service: SimulatedService) -> None:
    print(f"\nLogs for {service.config.name}")
    for entry in service.logs:
        print(entry)


def main() -> None:
    print("Linux Services: systemd, daemons, service configuration, startup services")

    manager = ServiceManager()

    dependency = SimulatedService(
        ServiceConfig(
            name="network-online.target.service",
            description="Network availability target",
            command=["/bin/true"],
        )
    )
    dependency.enabled = EnableState.STATIC
    manager.add(dependency)

    worker = demonstrate_unit_configuration()
    manager.add(worker)

    demonstrate_daemon_lifecycle(manager)
    print_logs(worker)

    demonstrate_failure_handling()
    demonstrate_startup_services()
    demonstrate_validation()
    demonstrate_unit_file_safety()
    inspect_linux_environment()

    print("\nOperational distinctions")
    print("systemd: the service manager and dependency-aware init system.")
    print("daemon: a long-running background process providing a service.")
    print("service configuration: declarative unit settings describing execution.")
    print("startup service: a service associated with a boot target through enablement.")

    print("\nProduction considerations")
    print("- Keep service processes least-privileged with a dedicated User= account.")
    print("- Prefer explicit absolute ExecStart paths for predictable execution.")
    print("- Use Restart=on-failure when automatic recovery is desirable without masking clean exits.")
    print("- Store secrets outside ordinary world-readable unit files.")
    print("- Validate dependencies and startup ordering before enabling a production service.")
    print("- Use journalctl and systemctl status when diagnosing real services.")
    print("- Avoid forceful service manipulation until dependency and failure behavior is understood.")


if __name__ == "__main__":
    main()
