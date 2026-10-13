"""
Windows Registry: structure, keys, values, configuration, and security.

Run with Python 3.10+ on Windows. The standard-library winreg module
provides registry access. Read-only demonstrations run without elevation.
Registry modifications require explicit opt-in and appropriate permissions.

On non-Windows systems, the registry simulator remains executable.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import tempfile
import unittest
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:
    winreg = None


HIVES = {
    "HKCU": "HKEY_CURRENT_USER",
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}


@dataclass
class RegistryValue:
    name: str
    value_type: str
    data: Any


@dataclass
class RegistryKey:
    path: str
    values: dict[str, RegistryValue] = field(default_factory=dict)
    subkeys: dict[str, "RegistryKey"] = field(default_factory=dict)


class RegistryError(Exception):
    """Base class for simulated registry errors."""


class RegistryPermissionError(RegistryError):
    """Raised when the simulated security policy denies an operation."""


class RegistryValidationError(RegistryError):
    """Raised when a path, value name, type, or value is invalid."""


class RegistrySimulator:
    """Case-insensitive registry model with typed values and access controls."""

    VALID_TYPES = {
        "REG_SZ",
        "REG_EXPAND_SZ",
        "REG_DWORD",
        "REG_QWORD",
        "REG_BINARY",
        "REG_MULTI_SZ",
    }

    def __init__(self) -> None:
        self.roots = {
            hive: RegistryKey(path=hive)
            for hive in HIVES
        }
        self.permissions: dict[str, set[str]] = {}
        self.audit_log: list[dict[str, str]] = []

    @staticmethod
    def normalize(path: str) -> tuple[str, list[str]]:
        if not isinstance(path, str) or not path.strip():
            raise RegistryValidationError("Registry path cannot be empty.")

        normalized = path.replace("/", "\\").strip("\\")
        parts = normalized.split("\\")
        hive = parts[0].upper()

        if hive not in HIVES:
            raise RegistryValidationError(f"Unsupported registry hive: {parts[0]}")

        if any(not part or part in {".", ".."} for part in parts[1:]):
            raise RegistryValidationError("Invalid registry path component.")

        if any("\x00" in part for part in parts):
            raise RegistryValidationError("Registry paths cannot contain NUL.")

        return hive, parts[1:]

    def _locate(self, path: str, create: bool = False) -> RegistryKey:
        hive, components = self.normalize(path)
        current = self.roots[hive]

        for component in components:
            actual = next(
                (name for name in current.subkeys
                 if name.casefold() == component.casefold()),
                None,
            )

            if actual is None:
                if not create:
                    raise RegistryError(f"Registry key not found: {path}")
                current.subkeys[component] = RegistryKey(
                    path=f"{current.path}\\{component}"
                )
                actual = component

            current = current.subkeys[actual]

        return current

    def set_permissions(self, path: str, allowed_operations: set[str]) -> None:
        self.normalize(path)
        permitted = {"read", "write", "delete", "enumerate"}

        if not allowed_operations.issubset(permitted):
            raise RegistryValidationError("Unknown permission.")

        self.permissions[path.casefold()] = set(allowed_operations)

    def _authorize(self, path: str, operation: str) -> None:
        self.normalize(path)
        components = path.casefold().replace("/", "\\").split("\\")
        ancestors = [
            "\\".join(components[:index])
            for index in range(1, len(components) + 1)
        ]

        for ancestor in ancestors:
            allowed = self.permissions.get(ancestor)
            if allowed is not None and operation not in allowed:
                self.audit_log.append({
                    "operation": operation,
                    "path": path,
                    "result": "DENIED",
                })
                raise RegistryPermissionError(
                    f"{operation} denied for {path}"
                )

        self.audit_log.append({
            "operation": operation,
            "path": path,
            "result": "ALLOWED",
        })

    @staticmethod
    def validate_value(name: str, value_type: str, data: Any) -> None:
        if not isinstance(name, str) or "\x00" in name:
            raise RegistryValidationError("Invalid registry value name.")

        if value_type not in RegistrySimulator.VALID_TYPES:
            raise RegistryValidationError("Unsupported registry value type.")

        if value_type in {"REG_SZ", "REG_EXPAND_SZ"}:
            if not isinstance(data, str) or "\x00" in data:
                raise RegistryValidationError("Expected a valid string.")

        elif value_type == "REG_DWORD":
            if type(data) is not int or not 0 <= data <= 0xFFFFFFFF:
                raise RegistryValidationError("REG_DWORD requires a 32-bit unsigned integer.")

        elif value_type == "REG_QWORD":
            if type(data) is not int or not 0 <= data <= 0xFFFFFFFFFFFFFFFF:
                raise RegistryValidationError("REG_QWORD requires a 64-bit unsigned integer.")

        elif value_type == "REG_BINARY":
            if not isinstance(data, bytes):
                raise RegistryValidationError("REG_BINARY requires bytes.")

        elif value_type == "REG_MULTI_SZ":
            if (
                not isinstance(data, list)
                or any(not isinstance(item, str) or "\x00" in item for item in data)
            ):
                raise RegistryValidationError("REG_MULTI_SZ requires a list of valid strings.")

    def create_key(self, path: str) -> None:
        self._authorize(path, "write")
        self._locate(path, create=True)

    def set_value(
        self, path: str, name: str, value_type: str, data: Any
    ) -> None:
        self._authorize(path, "write")
        self.validate_value(name, value_type, data)
        key = self._locate(path, create=True)
        actual_name = next(
            (existing for existing in key.values
             if existing.casefold() == name.casefold()),
            name,
        )
        key.values[actual_name] = RegistryValue(
            name=actual_name,
            value_type=value_type,
            data=data,
        )

    def get_value(self, path: str, name: str = "") -> RegistryValue:
        self._authorize(path, "read")
        key = self._locate(path)
        actual = next(
            (existing for existing in key.values
             if existing.casefold() == name.casefold()),
            None,
        )
        if actual is None:
            raise RegistryError(f"Value not found: {path}\\{name}")
        return key.values[actual]

    def list_subkeys(self, path: str) -> list[str]:
        self._authorize(path, "enumerate")
        return sorted(self._locate(path).subkeys, key=str.casefold)

    def delete_value(self, path: str, name: str) -> None:
        self._authorize(path, "delete")
        key = self._locate(path)
        actual = next(
            (existing for existing in key.values
             if existing.casefold() == name.casefold()),
            None,
        )
        if actual is None:
            raise RegistryError(f"Value not found: {path}\\{name}")
        del key.values[actual]

    def delete_key(self, path: str) -> None:
        hive, components = self.normalize(path)
        if not components:
            raise RegistryValidationError("A registry hive cannot be deleted.")

        self._authorize(path, "delete")
        key = self._locate(path)
        if key.values or key.subkeys:
            raise RegistryValidationError(
                "Only empty keys can be deleted by this simulator."
            )

        parent_path = "\\".join([hive, *components[:-1]])
        parent = self._locate(parent_path)
        del parent.subkeys[components[-1]]

    def export_json(self, path: str) -> str:
        key = self._locate(path)

        def serialize(node: RegistryKey) -> dict[str, Any]:
            return {
                "path": node.path,
                "values": {
                    name: {
                        "type": value.value_type,
                        "data": (
                            value.data.hex()
                            if value.value_type == "REG_BINARY"
                            else value.data
                        ),
                    }
                    for name, value in node.values.items()
                },
                "subkeys": {
                    name: serialize(child)
                    for name, child in node.subkeys.items()
                },
            }

        return json.dumps(serialize(key), indent=2)


class WindowsRegistryReader:
    """Read-only adapter for actual Windows registry keys."""

    def __init__(self) -> None:
        if winreg is None or platform.system() != "Windows":
            raise OSError("Actual registry access requires Windows.")

    @staticmethod
    def split_path(path: str) -> tuple[Any, str]:
        hive_name, components = RegistrySimulator.normalize(path)
        hive = getattr(winreg, HIVES[hive_name])
        return hive, "\\".join(components)

    def read_values(self, path: str, wow64_64: bool = False) -> list[dict[str, Any]]:
        hive, subkey = self.split_path(path)
        access = winreg.KEY_READ

        # On 64-bit Windows, the explicit flag selects the 64-bit registry view.
        if wow64_64 and hasattr(winreg, "KEY_WOW64_64KEY"):
            access |= winreg.KEY_WOW64_64KEY

        records = []
        with winreg.OpenKey(hive, subkey, 0, access) as key:
            index = 0
            while True:
                try:
                    name, data, value_type = winreg.EnumValue(key, index)
                except OSError:
                    break

                records.append({
                    "name": name,
                    "data": data,
                    "type": value_type,
                })
                index += 1

        return records


def demonstrate_simulator() -> None:
    registry = RegistrySimulator()
    base = r"HKCU\Software\ExampleCorp\DeploymentAgent"

    print("\nRegistry structure and typed configuration")
    registry.create_key(base)
    registry.set_value(base, "Channel", "REG_SZ", "stable")
    registry.set_value(base, "Enabled", "REG_DWORD", 1)
    registry.set_value(base, "RetryLimit", "REG_DWORD", 5)
    registry.set_value(
        base, "InstallPath", "REG_EXPAND_SZ",
        r"%ProgramFiles%\ExampleCorp\Agent",
    )
    registry.set_value(
        base, "TrustedServers", "REG_MULTI_SZ",
        ["updates.example.invalid", "mirror.example.invalid"],
    )

    for name in ("Channel", "Enabled", "RetryLimit", "InstallPath", "TrustedServers"):
        value = registry.get_value(base, name)
        print(f"{value.name}: {value.value_type} = {value.data!r}")

    registry.create_key(base + r"\Telemetry")
    registry.set_value(base + r"\Telemetry", "OptIn", "REG_DWORD", 0)
    print("Subkeys:", registry.list_subkeys(base))
    print("Export:\n", registry.export_json(base))

    print("\nValidation and access-control behavior")
    try:
        registry.set_value(base, "Enabled", "REG_DWORD", -1)
    except RegistryValidationError as error:
        print("Invalid DWORD rejected:", error)

    restricted = base + r"\ProtectedSettings"
    registry.create_key(restricted)
    registry.set_value(restricted, "PolicyVersion", "REG_DWORD", 3)
    registry.set_permissions(restricted, {"read", "enumerate"})

    try:
        registry.set_value(restricted, "PolicyVersion", "REG_DWORD", 4)
    except RegistryPermissionError as error:
        print("Unauthorized write rejected:", error)

    print("Audit events:", len(registry.audit_log))


def inspect_windows_registry(path: str) -> None:
    reader = WindowsRegistryReader()
    print(f"\nRead-only inspection: {path}")
    for value in reader.read_values(path):
        print(f"{value['name']!r}: type={value['type']}, data={value['data']!r}")


def run_tests() -> None:
    class RegistryTests(unittest.TestCase):
        def setUp(self) -> None:
            self.registry = RegistrySimulator()
            self.path = r"HKCU\Software\ExampleCorp\Tests"
            self.registry.create_key(self.path)

        def test_case_insensitive_lookup(self) -> None:
            self.registry.set_value(self.path, "Mode", "REG_SZ", "safe")
            self.assertEqual(self.registry.get_value(self.path, "mode").data, "safe")

        def test_dword_bounds(self) -> None:
            for invalid in (-1, 2**32, True):
                with self.assertRaises(RegistryValidationError):
                    self.registry.set_value(self.path, "Limit", "REG_DWORD", invalid)

        def test_binary_export(self) -> None:
            self.registry.set_value(self.path, "Fingerprint", "REG_BINARY", b"\x10\x20")
            self.assertIn("1020", self.registry.export_json(self.path))

        def test_permission_inheritance(self) -> None:
            child = self.path + r"\Child"
            self.registry.create_key(child)
            self.registry.set_permissions(self.path, {"read", "enumerate"})
            with self.assertRaises(RegistryPermissionError):
                self.registry.set_value(child, "Enabled", "REG_DWORD", 1)

        def test_empty_key_deletion(self) -> None:
            child = self.path + r"\Empty"
            self.registry.create_key(child)
            self.registry.delete_key(child)
            self.assertNotIn("Empty", self.registry.list_subkeys(self.path))

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RegistryTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Learn Windows Registry structure and configuration safely."
    )
    parser.add_argument(
        "--inspect",
        metavar="REGISTRY_PATH",
        help="Read values from an existing Windows registry key.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run built-in simulator tests.",
    )
    args = parser.parse_args()

    if args.inspect:
        inspect_windows_registry(args.inspect)
    else:
        demonstrate_simulator()

    if args.test:
        run_tests()


if __name__ == "__main__":
    main()
