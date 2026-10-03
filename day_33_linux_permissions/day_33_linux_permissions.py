#!/usr/bin/env python3
"""
Linux permissions laboratory.

This executable model demonstrates:
- Unix owner/group/other permission bits
- chmod-style symbolic and numeric changes
- chown-style ownership changes
- ACL-style named users and groups
- sudo and privilege boundaries
- directory traversal and file access
- setuid, setgid, and sticky-bit semantics
- umask and default permissions
- permission diagnostics and audit-style reporting

The program is intentionally self-contained and does not modify the host
filesystem. It models the kernel's permission decisions so that the same
rules can be explored safely on any operating system that runs Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import argparse
import os
import stat
from typing import Iterable


class Access(str, Enum):
    READ = "r"
    WRITE = "w"
    EXECUTE = "x"


@dataclass(frozen=True)
class Principal:
    uid: int
    username: str
    groups: frozenset[str] = frozenset()
    is_root: bool = False


@dataclass
class ACL:
    """
    A compact ACL model.

    access_users and access_groups represent named ACL entries.
    The mask limits named-user, named-group, and owning-group permissions.
    The mask does not limit the file owner or the other class.
    """

    access_users: dict[str, set[Access]] = field(default_factory=dict)
    access_groups: dict[str, set[Access]] = field(default_factory=dict)
    mask: set[Access] = field(
        default_factory=lambda: {Access.READ, Access.WRITE, Access.EXECUTE}
    )


@dataclass
class LinuxObject:
    path: str
    kind: str
    owner: str
    group: str
    mode: int
    acl: ACL | None = None
    parent: str | None = None

    @property
    def is_directory(self) -> bool:
        return self.kind == "directory"

    @property
    def is_symlink(self) -> bool:
        return self.kind == "symlink"


@dataclass
class Decision:
    allowed: bool
    class_used: str
    permissions: set[Access]
    reason: str


class PermissionErrorModel(Exception):
    """Raised for an operation that the simulated policy rejects."""


class PermissionSystem:
    def __init__(self) -> None:
        self.objects: dict[str, LinuxObject] = {}
        self.users: dict[str, Principal] = {}
        self.groups: dict[str, set[str]] = {}
        self.sudo_rules: dict[str, set[str]] = {}
        self.umask = 0o022
        self._build_environment()

    def _build_environment(self) -> None:
        self.add_user("root", 0, {"root"}, is_root=True)
        self.add_user("alice", 1001, {"developers"})
        self.add_user("bob", 1002, {"developers"})
        self.add_user("carol", 1003, {"auditors"})
        self.add_user("dave", 1004, {"operations"})

        self.sudo_rules["alice"] = {
            "/usr/bin/systemctl restart inventory.service",
            "/usr/bin/journalctl -u inventory.service",
        }
        self.sudo_rules["dave"] = {
            "/usr/bin/systemctl restart inventory.service",
            "/usr/bin/chown",
        }

        self.add_object(
            "/srv",
            "directory",
            "root",
            "root",
            0o755,
        )
        self.add_object(
            "/srv/inventory",
            "directory",
            "root",
            "operations",
            0o2775,
            parent="/srv",
        )
        self.add_object(
            "/srv/inventory/stock.csv",
            "file",
            "alice",
            "developers",
            0o664,
            parent="/srv/inventory",
        )
        self.add_object(
            "/srv/inventory/audit.log",
            "file",
            "root",
            "operations",
            0o640,
            parent="/srv/inventory",
        )
        self.add_object(
            "/srv/inventory/deploy.sh",
            "file",
            "root",
            "operations",
            0o750,
            parent="/srv/inventory",
        )
        self.add_object(
            "/srv/inventory/shared-report.txt",
            "file",
            "root",
            "operations",
            0o640,
            parent="/srv/inventory",
            acl=ACL(
                access_users={"carol": {Access.READ}},
                mask={Access.READ},
            ),
        )
        self.add_object(
            "/srv/inventory/drop",
            "directory",
            "root",
            "operations",
            0o3770,
            parent="/srv/inventory",
        )

    def add_user(
        self,
        username: str,
        uid: int,
        groups: Iterable[str],
        *,
        is_root: bool = False,
    ) -> None:
        group_set = frozenset(groups)
        self.users[username] = Principal(uid, username, group_set, is_root)
        for group in group_set:
            self.groups.setdefault(group, set()).add(username)

    def add_object(
        self,
        path: str,
        kind: str,
        owner: str,
        group: str,
        mode: int,
        *,
        parent: str | None = None,
        acl: ACL | None = None,
    ) -> None:
        if owner not in self.users:
            raise ValueError(f"Unknown owner: {owner}")
        self.objects[path] = LinuxObject(
            path=path,
            kind=kind,
            owner=owner,
            group=group,
            mode=mode,
            acl=acl,
            parent=parent,
        )

    @staticmethod
    def bits_to_set(bits: int) -> set[Access]:
        result: set[Access] = set()
        if bits & 4:
            result.add(Access.READ)
        if bits & 2:
            result.add(Access.WRITE)
        if bits & 1:
            result.add(Access.EXECUTE)
        return result

    @staticmethod
    def set_to_bits(permissions: set[Access]) -> int:
        return (
            (4 if Access.READ in permissions else 0)
            + (2 if Access.WRITE in permissions else 0)
            + (1 if Access.EXECUTE in permissions else 0)
        )

    @classmethod
    def mode_permissions(cls, mode: int, shift: int) -> set[Access]:
        return cls.bits_to_set((mode >> shift) & 0b111)

    @classmethod
    def format_mode(cls, mode: int) -> str:
        file_type = "d" if stat.S_ISDIR(mode | stat.S_IFDIR) and False else "-"
        # The model stores the object type separately, so this helper handles
        # permission and special bits without relying on host filesystem types.
        permissions = ""
        for shift in (6, 3, 0):
            permissions += "".join(
                [
                    "r" if Access.READ in cls.mode_permissions(mode, shift) else "-",
                    "w" if Access.WRITE in cls.mode_permissions(mode, shift) else "-",
                    "x" if Access.EXECUTE in cls.mode_permissions(mode, shift) else "-",
                ]
            )

        if mode & 0o4000:
            permissions = permissions[:2] + ("s" if mode & 0o100 else "S") + permissions[3:]
        if mode & 0o2000:
            permissions = permissions[:5] + ("s" if mode & 0o010 else "S") + permissions[6:]
        if mode & 0o1000:
            permissions = permissions[:-1] + ("t" if mode & 0o001 else "T")
        return file_type + permissions

    def describe(self, path: str) -> str:
        obj = self.require_object(path)
        acl_marker = "+" if obj.acl else ""
        return (
            f"{obj.kind:9} {obj.mode:04o}{acl_marker} "
            f"{obj.owner}:{obj.group} {obj.path}"
        )

    def require_object(self, path: str) -> LinuxObject:
        try:
            return self.objects[path]
        except KeyError:
            raise PermissionErrorModel(f"No such object: {path}")

    def _has_group(self, user: Principal, group: str) -> bool:
        return group in user.groups

    def _named_acl_permissions(
        self, obj: LinuxObject, user: Principal
    ) -> tuple[set[Access] | None, str]:
        if obj.acl is None:
            return None, ""

        if user.username in obj.acl.access_users:
            return (
                obj.acl.access_users[user.username] & obj.acl.mask,
                f"named user ACL entry for {user.username}",
            )

        for group in user.groups:
            if group in obj.acl.access_groups:
                return (
                    obj.acl.access_groups[group] & obj.acl.mask,
                    f"named group ACL entry for {group}",
                )

        return None, ""

    def permission_decision(
        self,
        username: str,
        path: str,
        requested: set[Access],
    ) -> Decision:
        user = self.users[username]
        obj = self.require_object(path)

        if user.is_root:
            return Decision(
                True,
                "root",
                {Access.READ, Access.WRITE, Access.EXECUTE},
                "root bypasses ordinary discretionary permission checks",
            )

        acl_permissions, acl_reason = self._named_acl_permissions(obj, user)

        if user.username == obj.owner:
            available = self.mode_permissions(obj.mode, 6)
            class_used = "owner"
            reason = "owner permission bits"
        elif acl_permissions is not None:
            available = acl_permissions
            class_used = "ACL"
            reason = acl_reason
        elif self._has_group(user, obj.group):
            available = self.mode_permissions(obj.mode, 3)
            if obj.acl:
                available &= obj.acl.mask
                reason = "owning-group bits limited by ACL mask"
            else:
                reason = "owning-group permission bits"
            class_used = "group"
        else:
            available = self.mode_permissions(obj.mode, 0)
            class_used = "other"
            reason = "other permission bits"

        missing = requested - available
        if missing:
            return Decision(
                False,
                class_used,
                available,
                f"{reason}; missing {''.join(sorted(p.value for p in missing))}",
            )

        return Decision(True, class_used, available, reason)

    def can_access(
        self,
        username: str,
        path: str,
        requested: set[Access],
    ) -> bool:
        return self.permission_decision(username, path, requested).allowed

    def check_parent_traversal(self, username: str, path: str) -> None:
        """
        Directory execute permission means search/traverse permission.

        A file can have read permission and still be inaccessible if the user
        cannot traverse one of its parent directories.
        """
        components = path.strip("/").split("/")
        current = ""
        for component in components[:-1]:
            current += "/" + component
            if current not in self.objects:
                raise PermissionErrorModel(f"Missing parent directory: {current}")
            if not self.can_access(username, current, {Access.EXECUTE}):
                raise PermissionErrorModel(
                    f"{username} cannot traverse {current}"
                )

    def read_file(self, username: str, path: str) -> str:
        self.check_parent_traversal(username, path)
        decision = self.permission_decision(username, path, {Access.READ})
        if not decision.allowed:
            raise PermissionErrorModel(
                f"read denied: {decision.reason}"
            )
        return f"simulated contents of {path}"

    def write_file(self, username: str, path: str) -> None:
        self.check_parent_traversal(username, path)
        decision = self.permission_decision(username, path, {Access.WRITE})
        if not decision.allowed:
            raise PermissionErrorModel(
                f"write denied: {decision.reason}"
            )
        print(f"WRITE permitted: {username} -> {path}")

    def create_file(self, username: str, directory: str, filename: str) -> str:
        directory_obj = self.require_object(directory)
        if not directory_obj.is_directory:
            raise PermissionErrorModel(f"{directory} is not a directory")

        decision = self.permission_decision(
            username,
            directory,
            {Access.WRITE, Access.EXECUTE},
        )
        if not decision.allowed:
            raise PermissionErrorModel(
                f"create denied in {directory}: {decision.reason}"
            )

        path = directory.rstrip("/") + "/" + filename
        if path in self.objects:
            raise PermissionErrorModel(f"{path} already exists")

        creator = self.users[username]
        group = directory_obj.group if directory_obj.mode & 0o2000 else (
            next(iter(creator.groups), "users")
        )
        requested_mode = 0o664
        effective_mode = requested_mode & ~self.umask

        self.add_object(
            path,
            "file",
            username,
            group,
            effective_mode,
            parent=directory,
        )
        return path

    def chmod(self, actor: str, path: str, new_mode: int) -> None:
        obj = self.require_object(path)
        actor_user = self.users[actor]

        if not actor_user.is_root and actor != obj.owner:
            raise PermissionErrorModel(
                "chmod denied: only the owner or a privileged actor may change mode"
            )
        if new_mode < 0 or new_mode > 0o7777:
            raise ValueError("mode must be between 0000 and 07777")

        obj.mode = new_mode
        print(f"chmod {new_mode:04o}: {path}")

    def chown(self, actor: str, path: str, new_owner: str, new_group: str) -> None:
        obj = self.require_object(path)
        actor_user = self.users[actor]

        if new_owner not in self.users:
            raise ValueError(f"unknown owner: {new_owner}")

        if not actor_user.is_root:
            raise PermissionErrorModel(
                "chown denied: changing ownership requires privileged authority "
                "in this model"
            )

        obj.owner = new_owner
        obj.group = new_group
        print(f"chown {new_owner}:{new_group} {path}")

    def set_acl_user(
        self,
        actor: str,
        path: str,
        username: str,
        permissions: set[Access],
    ) -> None:
        obj = self.require_object(path)
        if username not in self.users:
            raise ValueError(f"unknown user: {username}")

        if actor != obj.owner and not self.users[actor].is_root:
            raise PermissionErrorModel(
                "setfacl denied: actor must own the object or have privilege"
            )

        if obj.acl is None:
            obj.acl = ACL()

        obj.acl.access_users[username] = permissions
        print(
            f"ACL user:{username}={''.join(sorted(p.value for p in permissions))} "
            f"on {path}"
        )

    def set_acl_group(
        self,
        actor: str,
        path: str,
        group: str,
        permissions: set[Access],
    ) -> None:
        obj = self.require_object(path)
        if group not in self.groups:
            raise ValueError(f"unknown group: {group}")

        if actor != obj.owner and not self.users[actor].is_root:
            raise PermissionErrorModel(
                "setfacl denied: actor must own the object or have privilege"
            )

        if obj.acl is None:
            obj.acl = ACL()

        obj.acl.access_groups[group] = permissions
        print(
            f"ACL group:{group}={''.join(sorted(p.value for p in permissions))} "
            f"on {path}"
        )

    def set_acl_mask(
        self,
        actor: str,
        path: str,
        permissions: set[Access],
    ) -> None:
        obj = self.require_object(path)
        if actor != obj.owner and not self.users[actor].is_root:
            raise PermissionErrorModel(
                "setfacl mask denied: actor lacks ownership privilege"
            )
        if obj.acl is None:
            obj.acl = ACL()
        obj.acl.mask = permissions

    def sudo(self, username: str, command: str) -> Principal:
        user = self.users[username]
        if user.is_root:
            return user

        if command not in self.sudo_rules.get(username, set()):
            raise PermissionErrorModel(
                f"sudo policy denied command for {username}: {command}"
            )

        return self.users["root"]

    def execute_via_sudo(self, username: str, command: str) -> None:
        elevated = self.sudo(username, command)
        print(
            f"sudo permitted: {username} executes '{command}' "
            f"under effective identity {elevated.username}"
        )

    def ls_l(self, path_prefix: str = "/") -> None:
        for path in sorted(self.objects):
            if path.startswith(path_prefix.rstrip("/") + "/") or path == path_prefix:
                print(self.describe(path))

    def audit(self) -> list[str]:
        findings: list[str] = []

        for obj in self.objects.values():
            if obj.mode & 0o002:
                findings.append(f"world-writable object: {obj.path}")

            if obj.mode & 0o004 and obj.path.endswith(".log"):
                findings.append(f"world-readable log: {obj.path}")

            if obj.mode & 0o4000:
                findings.append(f"setuid object requires explicit review: {obj.path}")

            if obj.mode & 0o2000 and obj.is_directory:
                findings.append(
                    f"setgid directory shares group ownership: {obj.path}"
                )

            if obj.acl:
                for name, perms in obj.acl.access_users.items():
                    if Access.WRITE in perms:
                        findings.append(
                            f"named ACL grants write access to {name}: {obj.path}"
                        )

        return findings


def symbolic_mode_demo(system: PermissionSystem) -> None:
    print("\n=== chmod mechanics ===")
    path = "/srv/inventory/deploy.sh"
    print(system.describe(path))

    original = system.require_object(path).mode
    system.chmod("root", path, 0o740)
    print(system.describe(path))

    # Restore the original mode so later examples use the intended policy.
    system.chmod("root", path, original)

    print(
        "Numeric chmod uses three ordinary permission digits: "
        "owner, group, other. Special bits occupy the leading digit."
    )


def ownership_demo(system: PermissionSystem) -> None:
    print("\n=== ownership and chown ===")
    path = "/srv/inventory/stock.csv"
    print(system.describe(path))

    try:
        system.chown("alice", path, "bob", "developers")
    except PermissionErrorModel as exc:
        print(f"Expected boundary: {exc}")

    system.chown("root", path, "bob", "developers")
    print(system.describe(path))

    # Restore ownership for the remaining demonstrations.
    system.chown("root", path, "alice", "developers")


def acl_demo(system: PermissionSystem) -> None:
    print("\n=== ACL mechanics ===")
    path = "/srv/inventory/shared-report.txt"

    print(system.describe(path))
    carol = system.permission_decision("carol", path, {Access.READ})
    print(f"carol read: {carol.allowed}; {carol.reason}")

    try:
        system.write_file("carol", path)
    except PermissionErrorModel as exc:
        print(f"Expected ACL restriction: {exc}")

    system.set_acl_user(
        "root",
        path,
        "carol",
        {Access.READ, Access.WRITE},
    )
    system.set_acl_mask("root", path, {Access.READ, Access.WRITE})

    decision = system.permission_decision(
        "carol",
        path,
        {Access.WRITE},
    )
    print(
        f"carol write after ACL change: {decision.allowed}; "
        f"class={decision.class_used}; {decision.reason}"
    )

    # The mask can silently restrict a named ACL entry.
    system.set_acl_mask("root", path, {Access.READ})
    decision = system.permission_decision(
        "carol",
        path,
        {Access.WRITE},
    )
    print(
        f"carol write after mask reduction: {decision.allowed}; "
        f"available={''.join(sorted(p.value for p in decision.permissions))}"
    )


def traversal_demo(system: PermissionSystem) -> None:
    print("\n=== directory traversal ===")
    directory = system.require_object("/srv/inventory")
    original = directory.mode

    print(f"Before restriction: {system.describe('/srv/inventory')}")
    directory.mode = 0o770

    try:
        system.read_file("carol", "/srv/inventory/shared-report.txt")
    except PermissionErrorModel as exc:
        print(f"Traversal/access result: {exc}")

    # carol is not in operations, so group/other access to the directory matters.
    directory.mode = 0o755
    print(f"After restoring traversal: {system.describe('/srv/inventory')}")

    directory.mode = original


def umask_demo(system: PermissionSystem) -> None:
    print("\n=== umask and new objects ===")
    system.umask = 0o027
    path = system.create_file("alice", "/srv/inventory", "new-stock.csv")
    print(
        f"Created {path} with mode {system.require_object(path).mode:04o}; "
        f"requested 0664 minus umask 0027"
    )


def special_bits_demo(system: PermissionSystem) -> None:
    print("\n=== special permission bits ===")

    shared = system.require_object("/srv/inventory")
    print(
        f"setgid directory: mode={shared.mode:04o}. "
        "New files inherit the directory's group in this model."
    )

    drop = system.require_object("/srv/inventory/drop")
    print(
        f"sticky directory: mode={drop.mode:04o}. "
        "The sticky bit is intended to restrict deletion/renaming in shared "
        "directories even when several users can write there."
    )

    privileged_binary = LinuxObject(
        "/usr/local/bin/report-helper",
        "file",
        "root",
        "root",
        0o4750,
    )
    print(
        f"setuid example: {privileged_binary.path} mode={privileged_binary.mode:04o}. "
        "Execution can change the effective identity, which makes the program "
        "boundary security-critical."
    )


def sudo_demo(system: PermissionSystem) -> None:
    print("\n=== sudo and privilege boundaries ===")

    system.execute_via_sudo(
        "alice",
        "/usr/bin/systemctl restart inventory.service",
    )

    try:
        system.execute_via_sudo(
            "alice",
            "/usr/bin/chown",
        )
    except PermissionErrorModel as exc:
        print(f"Expected sudo policy denial: {exc}")

    try:
        system.execute_via_sudo(
            "bob",
            "/usr/bin/systemctl restart inventory.service",
        )
    except PermissionErrorModel as exc:
        print(f"Expected privilege boundary: {exc}")


def access_matrix_demo(system: PermissionSystem) -> None:
    print("\n=== access matrix ===")

    tests = [
        ("alice", "/srv/inventory/stock.csv", {Access.READ, Access.WRITE}),
        ("bob", "/srv/inventory/stock.csv", {Access.READ, Access.WRITE}),
        ("carol", "/srv/inventory/audit.log", {Access.READ}),
        ("dave", "/srv/inventory/audit.log", {Access.READ}),
        ("carol", "/srv/inventory/shared-report.txt", {Access.READ}),
        ("bob", "/srv/inventory/deploy.sh", {Access.EXECUTE}),
    ]

    for username, path, requested in tests:
        decision = system.permission_decision(username, path, requested)
        requested_text = "".join(sorted(p.value for p in requested))
        print(
            f"{username:5} {requested_text:2} {path:34} "
            f"{'ALLOW' if decision.allowed else 'DENY ':5} "
            f"[{decision.class_used}] {decision.reason}"
        )


def audit_demo(system: PermissionSystem) -> None:
    print("\n=== permission audit ===")
    findings = system.audit()
    if not findings:
        print("No findings.")
        return

    for finding in findings:
        print(f"- {finding}")


def real_filesystem_demo() -> None:
    print("\n=== host filesystem observation ===")
    current = os.stat(__file__)
    print(f"Current Python file: {os.path.abspath(__file__)}")
    print(f"Host mode: {stat.filemode(current.st_mode)}")
    print(f"Host UID: {current.st_uid}")
    print(f"Host GID: {current.st_gid}")
    print(
        "The laboratory above does not call chmod/chown on the host. "
        "That separation makes permission experiments safe and reproducible."
    )


def run_all() -> None:
    system = PermissionSystem()

    print("Linux Permission Laboratory")
    print("===========================")
    print("Mode model:", system.describe("/srv/inventory/stock.csv"))
    print("The simulated kernel evaluates identity, ACLs, mode bits, and traversal.")

    symbolic_mode_demo(system)
    ownership_demo(system)
    acl_demo(system)
    traversal_demo(system)
    umask_demo(system)
    special_bits_demo(system)
    sudo_demo(system)
    access_matrix_demo(system)
    audit_demo(system)
    real_filesystem_demo()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Explore Linux permission and privilege-boundary behavior."
    )
    parser.add_argument(
        "--path",
        default="/srv/inventory/stock.csv",
        help="Show the simulated object selected for inspection.",
    )
    parser.add_argument(
        "--user",
        default="alice",
        choices=["root", "alice", "bob", "carol", "dave"],
        help="Principal used for the access decision.",
    )
    parser.add_argument(
        "--access",
        default="rw",
        help="Requested access letters such as r, w, x, or rw.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run the complete laboratory.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.all or not args.path:
        run_all()
        return

    system = PermissionSystem()

    if args.path not in system.objects:
        raise SystemExit(f"Unknown simulated path: {args.path}")

    requested = {
        Access(letter)
        for letter in args.access
        if letter in {"r", "w", "x"}
    }

    if not requested:
        raise SystemExit("Access must contain at least one of r, w, or x.")

    print(system.describe(args.path))
    decision = system.permission_decision(args.user, args.path, requested)
    print(f"user={args.user}")
    print(f"requested={''.join(sorted(p.value for p in requested))}")
    print(f"decision={'ALLOW' if decision.allowed else 'DENY'}")
    print(f"class={decision.class_used}")
    print(f"available={''.join(sorted(p.value for p in decision.permissions))}")
    print(f"reason={decision.reason}")


if __name__ == "__main__":
    main()
