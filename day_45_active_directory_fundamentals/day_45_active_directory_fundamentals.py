#!/usr/bin/env python3
"""
Active Directory fundamentals laboratory.

Models domains, domain controllers, users, security groups, organizational
units, Group Policy Objects, policy links, authentication, authorization,
replication metadata, and administrative safeguards.

This is a standard-library simulation of Active Directory concepts. It does
not connect to Windows Server, implement Kerberos, or replace LDAP or AD DS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable
import hashlib
import json
import logging
import re
import uuid


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger("active_directory_lab")


class DirectoryError(Exception):
    """Base exception for directory operations."""


class ValidationError(DirectoryError):
    """Raised when a directory object violates a data rule."""


class DuplicateObjectError(DirectoryError):
    """Raised when a directory identifier is already in use."""


class ObjectNotFoundError(DirectoryError):
    """Raised when an object cannot be located."""


class AuthorizationError(DirectoryError):
    """Raised when a principal lacks the required permission."""


class PolicyError(DirectoryError):
    """Raised when a policy configuration is invalid."""


class ObjectType(str, Enum):
    USER = "user"
    GROUP = "group"
    OU = "organizational_unit"
    COMPUTER = "computer"


class GroupScope(str, Enum):
    DOMAIN_LOCAL = "domain_local"
    GLOBAL = "global"
    UNIVERSAL = "universal"


class GroupType(str, Enum):
    SECURITY = "security"
    DISTRIBUTION = "distribution"


class PolicySetting(str, Enum):
    PASSWORD_MIN_LENGTH = "password_min_length"
    ACCOUNT_LOCKOUT_THRESHOLD = "account_lockout_threshold"
    REQUIRE_MFA = "require_mfa"
    USB_STORAGE_ALLOWED = "usb_storage_allowed"
    SCREEN_LOCK_MINUTES = "screen_lock_minutes"
    FIREWALL_ENABLED = "firewall_enabled"


@dataclass
class DirectoryObject:
    name: str
    object_type: ObjectType
    distinguished_name: str
    object_guid: str = field(default_factory=lambda: str(uuid.uuid4()))
    enabled: bool = True
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class User(DirectoryObject):
    sam_account_name: str = ""
    user_principal_name: str = ""
    department: str = ""
    failed_logons: int = 0
    locked: bool = False
    password_last_set: datetime | None = None
    password_hash: str | None = None
    mfa_registered: bool = False


@dataclass
class SecurityGroup(DirectoryObject):
    scope: GroupScope = GroupScope.GLOBAL
    group_type: GroupType = GroupType.SECURITY
    member_guids: set[str] = field(default_factory=set)


@dataclass
class OrganizationalUnit(DirectoryObject):
    parent_dn: str | None = None
    protected_from_accidental_deletion: bool = True
    child_ous: set[str] = field(default_factory=set)


@dataclass
class Computer(DirectoryObject):
    operating_system: str = "Windows"
    secure_channel_healthy: bool = True


@dataclass
class GroupPolicyObject:
    name: str
    settings: dict[PolicySetting, object]
    guid: str = field(default_factory=lambda: str(uuid.uuid4()))
    enabled: bool = True
    user_configuration_enabled: bool = True
    computer_configuration_enabled: bool = True


@dataclass
class PolicyLink:
    gpo_guid: str
    target_dn: str
    order: int = 1
    enforced: bool = False
    disabled: bool = False
    block_inheritance: bool = False


@dataclass
class DomainController:
    name: str
    domain_dns_name: str
    site: str
    roles: set[str] = field(default_factory=set)
    writable: bool = True
    global_catalog: bool = True
    replication_watermark: int = 0
    reachable: bool = True


class ActiveDirectoryDomain:
    """
    In-memory directory with simplified object identity and policy processing.

    A real AD DS domain stores objects in the directory database and uses
    LDAP, Kerberos, DNS, replication, and domain-controller security rules.
    """

    RESERVED_NAMES = {"administrator", "krbtgt", "guest"}

    def __init__(self, dns_name: str, netbios_name: str):
        dns_name = dns_name.strip().lower()
        netbios_name = netbios_name.strip().upper()

        if not self._valid_dns_name(dns_name):
            raise ValidationError(f"Invalid domain DNS name: {dns_name}")
        if not re.fullmatch(r"[A-Z0-9-]{1,15}", netbios_name):
            raise ValidationError("NetBIOS name must contain 1-15 valid characters.")

        self.dns_name = dns_name
        self.netbios_name = netbios_name
        self.domain_dn = ",".join(
            f"DC={label}" for label in dns_name.split(".")
        )
        self.objects: dict[str, DirectoryObject] = {}
        self.sam_index: dict[str, str] = {}
        self.upn_index: dict[str, str] = {}
        self.groups: dict[str, SecurityGroup] = {}
        self.ous: dict[str, OrganizationalUnit] = {}
        self.computers: dict[str, Computer] = {}
        self.gpos: dict[str, GroupPolicyObject] = {}
        self.policy_links: list[PolicyLink] = []
        self.controllers: dict[str, DomainController] = {}
        self.events: list[dict[str, object]] = []
        self.change_version = 0
        self.max_failed_logons = 5

        self.root_ou = OrganizationalUnit(
            name="Domain Root",
            object_type=ObjectType.OU,
            distinguished_name=self.domain_dn,
            protected_from_accidental_deletion=True,
        )
        self.ous[self.root_ou.distinguished_name.lower()] = self.root_ou
        self.objects[self.root_ou.object_guid] = self.root_ou

    @staticmethod
    def _valid_dns_name(value: str) -> bool:
        if len(value) > 253 or "." not in value:
            return False
        labels = value.split(".")
        return all(
            len(label) <= 63
            and re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
                label,
            )
            for label in labels
        )

    @staticmethod
    def _normalize_sam(value: str) -> str:
        value = value.strip()
        if not value or len(value) > 20:
            raise ValidationError(
                "sAMAccountName must contain 1-20 non-empty characters."
            )
        if any(character in value for character in '\\/"[]:;|=,+*?<>'):
            raise ValidationError("sAMAccountName contains an invalid character.")
        return value.casefold()

    def _record(self, action: str, object_guid: str, details: str) -> None:
        self.change_version += 1
        self.events.append({
            "version": self.change_version,
            "time": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "object_guid": object_guid,
            "details": details,
        })

    def _assert_unique_dn(self, dn: str) -> None:
        if any(
            obj.distinguished_name.casefold() == dn.casefold()
            for obj in self.objects.values()
        ):
            raise DuplicateObjectError(f"Distinguished name already exists: {dn}")

    def add_controller(self, controller: DomainController) -> None:
        key = controller.name.casefold()
        if key in self.controllers:
            raise DuplicateObjectError("Domain controller already registered.")
        if controller.domain_dns_name.casefold() != self.dns_name:
            raise ValidationError("Controller belongs to a different domain.")
        if not controller.name.strip():
            raise ValidationError("Controller name cannot be empty.")
        self.controllers[key] = controller
        self._record("controller_registered", controller.name, controller.site)

    def create_ou(
        self,
        name: str,
        parent_dn: str | None = None,
        protect: bool = True,
    ) -> OrganizationalUnit:
        name = name.strip()
        if not name or "," in name:
            raise ValidationError("OU name cannot be empty or contain a comma.")

        parent_dn = (parent_dn or self.domain_dn).strip()
        parent = self.ous.get(parent_dn.casefold())
        if parent is None:
            raise ObjectNotFoundError(f"Parent OU not found: {parent_dn}")

        dn = f"OU={name},{parent.distinguished_name}"
        self._assert_unique_dn(dn)
        ou = OrganizationalUnit(
            name=name,
            object_type=ObjectType.OU,
            distinguished_name=dn,
            parent_dn=parent.distinguished_name,
            protected_from_accidental_deletion=protect,
        )
        self.ous[dn.casefold()] = ou
        self.objects[ou.object_guid] = ou
        parent.child_ous.add(ou.object_guid)
        self._record("ou_created", ou.object_guid, dn)
        return ou

    def create_user(
        self,
        display_name: str,
        sam_account_name: str,
        department: str,
        ou_dn: str,
        password: str,
        mfa_registered: bool = False,
    ) -> User:
        display_name = display_name.strip()
        department = department.strip()
        if not display_name:
            raise ValidationError("Display name is required.")
        if not department:
            raise ValidationError("Department is required.")

        sam = self._normalize_sam(sam_account_name)
        if sam in self.RESERVED_NAMES:
            raise ValidationError("Reserved built-in account name.")
        if sam in self.sam_index:
            raise DuplicateObjectError("sAMAccountName already exists.")

        ou = self.ous.get(ou_dn.casefold())
        if ou is None:
            raise ObjectNotFoundError(f"Target OU not found: {ou_dn}")

        upn = f"{sam_account_name.strip()}@{self.dns_name}".lower()
        if upn in self.upn_index:
            raise DuplicateObjectError("User principal name already exists.")

        # This demonstration uses a one-way digest only to illustrate that
        # directory credentials must not be stored as plaintext. Production
        # passwords must use supported AD DS credential management.
        if len(password) < 12:
            raise ValidationError("Demonstration password must be at least 12 characters.")
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

        dn = f"CN={display_name},{ou.distinguished_name}"
        self._assert_unique_dn(dn)

        user = User(
            name=display_name,
            object_type=ObjectType.USER,
            distinguished_name=dn,
            sam_account_name=sam_account_name.strip(),
            user_principal_name=upn,
            department=department,
            password_hash=password_hash,
            password_last_set=datetime.now(timezone.utc),
            mfa_registered=mfa_registered,
        )
        self.objects[user.object_guid] = user
        self.sam_index[sam] = user.object_guid
        self.upn_index[upn] = user.object_guid
        self._record("user_created", user.object_guid, dn)
        return user

    def create_group(
        self,
        name: str,
        ou_dn: str,
        scope: GroupScope = GroupScope.GLOBAL,
        group_type: GroupType = GroupType.SECURITY,
    ) -> SecurityGroup:
        ou = self.ous.get(ou_dn.casefold())
        if ou is None:
            raise ObjectNotFoundError(f"Target OU not found: {ou_dn}")
        if not name.strip():
            raise ValidationError("Group name cannot be empty.")

        dn = f"CN={name.strip()},{ou.distinguished_name}"
        self._assert_unique_dn(dn)
        group = SecurityGroup(
            name=name.strip(),
            object_type=ObjectType.GROUP,
            distinguished_name=dn,
            scope=scope,
            group_type=group_type,
        )
        self.groups[group.object_guid] = group
        self.objects[group.object_guid] = group
        self._record("group_created", group.object_guid, dn)
        return group

    def add_group_member(self, group_guid: str, member_guid: str) -> None:
        group = self.groups.get(group_guid)
        member = self.objects.get(member_guid)
        if group is None or member is None:
            raise ObjectNotFoundError("Group or member does not exist.")
        if group.group_type is not GroupType.SECURITY:
            raise ValidationError(
                "Distribution groups organize messaging; they do not grant access."
            )
        if member_guid == group_guid:
            raise ValidationError("A group cannot contain itself.")

        # Reject cycles in nested group membership.
        if isinstance(member, SecurityGroup):
            if self._group_contains(member_guid, group_guid, set()):
                raise ValidationError("Nested group membership would create a cycle.")

        group.member_guids.add(member_guid)
        self._record("group_member_added", group_guid, member_guid)

    def _group_contains(
        self, start_guid: str, target_guid: str, visited: set[str]
    ) -> bool:
        if start_guid == target_guid:
            return True
        if start_guid in visited:
            return False
        visited.add(start_guid)
        group = self.groups.get(start_guid)
        if group is None:
            return False
        return any(
            isinstance(self.objects.get(member_guid), SecurityGroup)
            and self._group_contains(member_guid, target_guid, visited)
            for member_guid in group.member_guids
        )

    def effective_security_groups(self, principal_guid: str) -> set[str]:
        if principal_guid not in self.objects:
            raise ObjectNotFoundError("Principal does not exist.")

        effective: set[str] = set()
        pending = [principal_guid]
        visited: set[str] = set()

        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            for group in self.groups.values():
                if (
                    group.group_type is GroupType.SECURITY
                    and current in group.member_guids
                    and group.enabled
                ):
                    if group.object_guid not in effective:
                        effective.add(group.object_guid)
                        pending.append(group.object_guid)
        return effective

    def register_gpo(self, gpo: GroupPolicyObject) -> None:
        if gpo.guid in self.gpos:
            raise DuplicateObjectError("GPO identifier already exists.")
        for setting, value in gpo.settings.items():
            self._validate_policy_setting(setting, value)
        self.gpos[gpo.guid] = gpo
        self._record("gpo_registered", gpo.guid, gpo.name)

    @staticmethod
    def _validate_policy_setting(setting: PolicySetting, value: object) -> None:
        if setting is PolicySetting.PASSWORD_MIN_LENGTH:
            if not isinstance(value, int) or isinstance(value, bool) or not 8 <= value <= 128:
                raise PolicyError("Password minimum length must be between 8 and 128.")
        elif setting is PolicySetting.ACCOUNT_LOCKOUT_THRESHOLD:
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 20:
                raise PolicyError("Lockout threshold must be between 0 and 20.")
        elif setting in {
            PolicySetting.REQUIRE_MFA,
            PolicySetting.USB_STORAGE_ALLOWED,
            PolicySetting.FIREWALL_ENABLED,
        }:
            if not isinstance(value, bool):
                raise PolicyError(f"{setting.value} must be Boolean.")
        elif setting is PolicySetting.SCREEN_LOCK_MINUTES:
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 240:
                raise PolicyError("Screen lock must be between 1 and 240 minutes.")

    def link_gpo(
        self,
        gpo_guid: str,
        target_dn: str,
        order: int = 1,
        enforced: bool = False,
        disabled: bool = False,
    ) -> None:
        if gpo_guid not in self.gpos:
            raise ObjectNotFoundError("GPO not found.")
        if target_dn.casefold() not in self.ous:
            raise ObjectNotFoundError("GPO target must be an existing OU or domain root.")
        if order < 1:
            raise ValidationError("Link order must be positive.")

        self.policy_links.append(PolicyLink(
            gpo_guid=gpo_guid,
            target_dn=target_dn,
            order=order,
            enforced=enforced,
            disabled=disabled,
        ))
        self._record("gpo_linked", gpo_guid, target_dn)

    def _ancestor_ous(self, target_dn: str) -> list[OrganizationalUnit]:
        current = self.ous.get(target_dn.casefold())
        if current is None:
            raise ObjectNotFoundError("OU not found.")
        result = []
        while current is not None:
            result.append(current)
            if current.parent_dn is None:
                break
            current = self.ous.get(current.parent_dn.casefold())
        result.reverse()
        return result

    def effective_policy(self, target_dn: str) -> dict[str, object]:
        """
        Approximate policy processing for a computer or OU target.

        Links at a given scope are processed by link order. More specific,
        non-enforced settings can override parent settings. Enforced links
        resist inheritance blocking and normal descendant overrides in the
        simplified model. This is not a replacement for gpresult or RSOP.
        """
        ancestors = self._ancestor_ous(target_dn)
        links_by_scope: dict[str, list[PolicyLink]] = {}
        for link in self.policy_links:
            if not link.disabled:
                links_by_scope.setdefault(link.target_dn.casefold(), []).append(link)

        result: dict[str, object] = {}
        enforced_values: dict[str, object] = {}

        for ou in ancestors:
            links = sorted(
                links_by_scope.get(ou.distinguished_name.casefold(), []),
                key=lambda item: item.order,
                reverse=True,
            )
            for link in links:
                gpo = self.gpos[link.gpo_guid]
                if not gpo.enabled or not gpo.computer_configuration_enabled:
                    continue
                for setting, value in gpo.settings.items():
                    if link.enforced:
                        enforced_values[setting.value] = value
                    elif setting.value not in enforced_values:
                        result[setting.value] = value

        result.update(enforced_values)
        return result

    def authenticate(self, sam_account_name: str, password: str) -> bool:
        key = self._normalize_sam(sam_account_name)
        user_guid = self.sam_index.get(key)
        if user_guid is None:
            raise AuthorizationError("Invalid credentials.")

        user = self.objects[user_guid]
        assert isinstance(user, User)

        if not user.enabled or user.locked:
            self._record("authentication_denied", user_guid, "disabled_or_locked")
            raise AuthorizationError("Account is disabled or locked.")

        candidate = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if candidate != user.password_hash:
            user.failed_logons += 1
            if user.failed_logons >= self.max_failed_logons:
                user.locked = True
                self._record("account_locked", user_guid, "failure_threshold_reached")
            else:
                self._record("authentication_failed", user_guid, "invalid_password")
            raise AuthorizationError("Invalid credentials.")

        user.failed_logons = 0
        self._record("authentication_succeeded", user_guid, "simulation_only")
        return True

    def authorize_group_access(
        self, principal_guid: str, required_group_guid: str
    ) -> bool:
        principal = self.objects.get(principal_guid)
        if principal is None or not principal.enabled:
            raise AuthorizationError("Principal is missing or disabled.")
        if required_group_guid not in self.groups:
            raise ObjectNotFoundError("Required group does not exist.")

        if required_group_guid not in self.effective_security_groups(principal_guid):
            raise AuthorizationError("Required security group membership is absent.")
        return True

    def delete_ou(self, ou_dn: str) -> None:
        ou = self.ous.get(ou_dn.casefold())
        if ou is None:
            raise ObjectNotFoundError("OU not found.")
        if ou.protected_from_accidental_deletion:
            raise AuthorizationError("OU is protected from accidental deletion.")
        if ou.child_ous:
            raise ValidationError("Cannot delete an OU that contains child OUs.")

        children = [
            obj for obj in self.objects.values()
            if obj.distinguished_name.casefold().endswith(
                "," + ou.distinguished_name.casefold()
            )
        ]
        if children:
            raise ValidationError("Cannot delete an OU that contains directory objects.")

        del self.ous[ou.distinguished_name.casefold()]
        self.objects.pop(ou.object_guid, None)
        parent = self.ous.get((ou.parent_dn or "").casefold())
        if parent:
            parent.child_ous.discard(ou.object_guid)
        self._record("ou_deleted", ou.object_guid, ou.distinguished_name)

    def replication_report(self) -> list[dict[str, object]]:
        report = []
        for controller in self.controllers.values():
            report.append({
                "controller": controller.name,
                "site": controller.site,
                "reachable": controller.reachable,
                "local_version": controller.replication_watermark,
                "domain_version": self.change_version,
                "lag": max(0, self.change_version - controller.replication_watermark),
            })
        return report

    def export_audit_json(self) -> str:
        return json.dumps(self.events, indent=2, sort_keys=True)


def demonstrate() -> None:
    print("Active Directory Fundamentals Laboratory")

    domain = ActiveDirectoryDomain("corp.example.com", "CORP")

    dc1 = DomainController(
        name="DC01",
        domain_dns_name=domain.dns_name,
        site="Lucknow",
        roles={"PDC Emulator", "RID Master", "Infrastructure Master"},
        replication_watermark=0,
    )
    dc2 = DomainController(
        name="DC02",
        domain_dns_name=domain.dns_name,
        site="Delhi",
        replication_watermark=0,
    )
    domain.add_controller(dc1)
    domain.add_controller(dc2)

    engineering = domain.create_ou("Engineering")
    privileged = domain.create_ou("Privileged", engineering.distinguished_name)
    employees = domain.create_ou("Employees")

    developer = domain.create_user(
        "Riya Sharma",
        "riya.sharma",
        "Engineering",
        engineering.distinguished_name,
        "Engineering!2026Secure",
        mfa_registered=True,
    )
    administrator = domain.create_user(
        "Dev Operations",
        "devops.admin",
        "IT",
        privileged.distinguished_name,
        "Privileged!Access2026",
        mfa_registered=True,
    )

    developers = domain.create_group(
        "Engineering-Developers", engineering.distinguished_name
    )
    privileged_access = domain.create_group(
        "Production-Administrators",
        privileged.distinguished_name,
        scope=GroupScope.DOMAIN_LOCAL,
    )

    domain.add_group_member(developers.object_guid, developer.object_guid)
    domain.add_group_member(privileged_access.object_guid, administrator.object_guid)
    domain.add_group_member(privileged_access.object_guid, developers.object_guid)

    print(f"\nDomain: {domain.dns_name}")
    print(f"Distinguished name: {domain.domain_dn}")
    print(f"User DN: {developer.distinguished_name}")
    print(f"Developer's effective groups: {len(domain.effective_security_groups(developer.object_guid))}")

    try:
        domain.authorize_group_access(developer.object_guid, privileged_access.object_guid)
        print("Production access granted.")
    except AuthorizationError as exc:
        print(f"Production access denied: {exc}")

    domain.authorize_group_access(administrator.object_guid, privileged_access.object_guid)
    print("Administrator production group access granted.")

    security_baseline = GroupPolicyObject(
        name="Corporate Security Baseline",
        settings={
            PolicySetting.PASSWORD_MIN_LENGTH: 14,
            PolicySetting.ACCOUNT_LOCKOUT_THRESHOLD: 5,
            PolicySetting.REQUIRE_MFA: True,
            PolicySetting.USB_STORAGE_ALLOWED: False,
            PolicySetting.SCREEN_LOCK_MINUTES: 10,
            PolicySetting.FIREWALL_ENABLED: True,
        },
    )
    domain.register_gpo(security_baseline)
    domain.link_gpo(security_baseline.guid, domain.domain_dn, order=1, enforced=True)

    workstation_policy = GroupPolicyObject(
        name="Engineering Workstation Policy",
        settings={
            PolicySetting.USB_STORAGE_ALLOWED: True,
            PolicySetting.SCREEN_LOCK_MINUTES: 15,
        },
    )
    domain.register_gpo(workstation_policy)
    domain.link_gpo(
        workstation_policy.guid,
        engineering.distinguished_name,
        order=1,
    )

    print("\nEffective Engineering policy:")
    for setting, value in sorted(
        domain.effective_policy(engineering.distinguished_name).items()
    ):
        print(f"  {setting}: {value}")

    print("\nAuthentication simulation:")
    print("Successful authentication:", domain.authenticate(
        "riya.sharma", "Engineering!2026Secure"
    ))

    print("\nReplication status before simulated convergence:")
    for item in domain.replication_report():
        print(f"  {item}")

    # A watermark represents observed convergence in this educational model.
    dc1.replication_watermark = domain.change_version
    dc2.replication_watermark = domain.change_version - 3

    print("\nReplication status after simulated convergence:")
    for item in domain.replication_report():
        print(f"  {item}")

    try:
        domain.create_user(
            "Duplicate Riya",
            "RIYA.SHARMA",
            "Engineering",
            employees.distinguished_name,
            "Another!Secure2026",
        )
    except DuplicateObjectError as exc:
        print(f"\nDuplicate identity rejected: {exc}")

    try:
        domain.create_ou("Unsafe,OU", protect=True)
    except ValidationError as exc:
        print(f"Invalid OU rejected: {exc}")

    try:
        domain.delete_ou(engineering.distinguished_name)
    except AuthorizationError as exc:
        print(f"Protected OU deletion rejected: {exc}")

    print("\nAudit event count:", len(domain.events))
    print("Last audit event:", json.dumps(domain.events[-1], indent=2))


if __name__ == "__main__":
    demonstrate()
