"""
Active Directory Architecture: Forests, Trees, Domains, Trusts, LDAP, and DNS.

A self-contained educational simulator of a directory-services environment.
The model illustrates logical hierarchy, namespace relationships, trust
direction, LDAP searches, DNS service discovery, authentication boundaries,
and operational diagnostics.

This is a conceptual simulator, not a replacement for Microsoft Active
Directory Domain Services, Kerberos, LDAP servers, or Windows DNS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable
import ipaddress
import json


class DirectoryError(Exception):
    """Base exception for directory model failures."""


class ValidationError(DirectoryError):
    """Raised when directory configuration is invalid."""


class LookupErrorAD(DirectoryError):
    """Raised when a directory object or domain cannot be found."""


class TrustDirection(Enum):
    OUTBOUND = "outbound"
    INBOUND = "inbound"
    BIDIRECTIONAL = "bidirectional"


class TrustScope(Enum):
    DOMAIN = "domain"
    FOREST = "forest"
    EXTERNAL = "external"


class ReviewResult(Enum):
    ALLOWED = "allowed"
    DENIED = "denied"


@dataclass(frozen=True)
class DirectoryObject:
    distinguished_name: str
    object_class: str
    attributes: dict[str, str | tuple[str, ...]]

    def __post_init__(self) -> None:
        if not self.distinguished_name.strip():
            raise ValidationError("Distinguished name cannot be empty.")
        if not self.object_class.strip():
            raise ValidationError("Object class cannot be empty.")
        if not self.distinguished_name.casefold().startswith(
            ("cn=", "ou=", "dc=")
        ):
            raise ValidationError("Invalid distinguished-name prefix.")

    def attribute(self, name: str) -> str | tuple[str, ...] | None:
        for key, value in self.attributes.items():
            if key.casefold() == name.casefold():
                return value
        return None


@dataclass
class Domain:
    name: str
    forest_name: str
    parent_domain: str | None = None
    objects: dict[str, DirectoryObject] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.name = normalize_dns_name(self.name)
        self.forest_name = normalize_dns_name(self.forest_name)
        if self.parent_domain is not None:
            self.parent_domain = normalize_dns_name(self.parent_domain)

    def add_object(self, obj: DirectoryObject) -> None:
        key = obj.distinguished_name.casefold()
        if key in self.objects:
            raise ValidationError(
                f"Duplicate distinguished name in {self.name}: "
                f"{obj.distinguished_name}"
            )
        self.objects[key] = obj

    def search(
        self,
        object_class: str | None = None,
        attribute_name: str | None = None,
        attribute_value: str | None = None,
    ) -> list[DirectoryObject]:
        results = []
        for obj in self.objects.values():
            if object_class and obj.object_class.casefold() != (
                object_class.casefold()
            ):
                continue
            if attribute_name is not None:
                value = obj.attribute(attribute_name)
                if value is None:
                    continue
                values = value if isinstance(value, tuple) else (value,)
                if not any(
                    item.casefold() == (attribute_value or "").casefold()
                    for item in values
                ):
                    continue
            results.append(obj)
        return sorted(results, key=lambda item: item.distinguished_name)

    def ldap_base_dn(self) -> str:
        return ",".join(
            f"DC={label}" for label in self.name.split(".")
        )


@dataclass
class Forest:
    root_domain: str
    domains: dict[str, Domain] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.root_domain = normalize_dns_name(self.root_domain)

    def add_domain(self, domain: Domain) -> None:
        if domain.name in self.domains:
            raise ValidationError(f"Domain already exists: {domain.name}")

        if domain.forest_name != self.root_domain:
            raise ValidationError(
                f"{domain.name} declares forest {domain.forest_name}, "
                f"not {self.root_domain}."
            )

        if not self.domains:
            if domain.name != self.root_domain:
                raise ValidationError(
                    "The first domain must be the forest root domain."
                )
        else:
            parent = domain.parent_domain
            if parent is None or parent not in self.domains:
                raise ValidationError(
                    "A child domain must identify an existing parent domain."
                )
            if not domain.name.endswith("." + parent):
                raise ValidationError(
                    f"{domain.name} is not a child DNS namespace of {parent}."
                )

        self.domains[domain.name] = domain

    def tree_roots(self) -> list[str]:
        return sorted(
            name for name, domain in self.domains.items()
            if domain.parent_domain is None
        )

    def describe(self) -> dict[str, object]:
        return {
            "forest_root": self.root_domain,
            "domains": [
                {
                    "name": domain.name,
                    "parent": domain.parent_domain,
                    "ldap_base_dn": domain.ldap_base_dn(),
                    "object_count": len(domain.objects),
                }
                for domain in sorted(
                    self.domains.values(), key=lambda item: item.name
                )
            ],
        }


@dataclass(frozen=True)
class Trust:
    source_forest: str
    target_forest: str
    direction: TrustDirection
    scope: TrustScope
    transitive: bool = True
    enabled: bool = True


@dataclass(frozen=True)
class DnsRecord:
    name: str
    record_type: str
    value: str
    priority: int = 0
    port: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", normalize_dns_name(self.name))
        record_type = self.record_type.upper()
        if record_type not in {"A", "AAAA", "CNAME", "SRV"}:
            raise ValidationError(f"Unsupported DNS record type: {record_type}")
        object.__setattr__(self, "record_type", record_type)

        if record_type == "A":
            try:
                if ipaddress.ip_address(self.value).version != 4:
                    raise ValidationError("An A record requires IPv4.")
            except ValueError as exc:
                raise ValidationError("Invalid IPv4 address.") from exc

        if record_type == "AAAA":
            try:
                if ipaddress.ip_address(self.value).version != 6:
                    raise ValidationError("An AAAA record requires IPv6.")
            except ValueError as exc:
                raise ValidationError("Invalid IPv6 address.") from exc

        if record_type == "SRV":
            if not self.value.strip() or not self.value.endswith("."):
                raise ValidationError(
                    "SRV target must be a non-empty absolute DNS name."
                )
            if self.port is None or not 1 <= self.port <= 65535:
                raise ValidationError("SRV port must be between 1 and 65535.")


def normalize_dns_name(name: str) -> str:
    name = name.strip().rstrip(".").casefold()
    if not name or len(name) > 253:
        raise ValidationError("DNS name is empty or too long.")

    labels = name.split(".")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
        ):
            raise ValidationError(f"Invalid DNS label: {label!r}")
    return name


class DirectoryEnvironment:
    def __init__(self) -> None:
        self.forests: dict[str, Forest] = {}
        self.trusts: list[Trust] = []
        self.dns_records: dict[tuple[str, str], DnsRecord] = {}

    def add_forest(self, forest: Forest) -> None:
        if forest.root_domain in self.forests:
            raise ValidationError(
                f"Forest already exists: {forest.root_domain}"
            )
        self.forests[forest.root_domain] = forest

    def add_trust(self, trust: Trust) -> None:
        source = normalize_dns_name(trust.source_forest)
        target = normalize_dns_name(trust.target_forest)
        if source == target:
            raise ValidationError("A forest cannot trust itself.")
        if source not in self.forests or target not in self.forests:
            raise LookupErrorAD("Both forests must exist before adding trust.")
        if any(
            item.source_forest == source
            and item.target_forest == target
            and item.scope == trust.scope
            for item in self.trusts
        ):
            raise ValidationError("Duplicate trust configuration.")

        self.trusts.append(
            Trust(
                source,
                target,
                trust.direction,
                trust.scope,
                trust.transitive,
                trust.enabled,
            )
        )

    def add_dns_record(self, record: DnsRecord) -> None:
        key = (record.name, record.record_type)
        if key in self.dns_records:
            raise ValidationError(
                f"Duplicate {record.record_type} record for {record.name}."
            )
        self.dns_records[key] = record

    def find_domain(self, domain_name: str) -> Domain:
        name = normalize_dns_name(domain_name)
        for forest in self.forests.values():
            if name in forest.domains:
                return forest.domains[name]
        raise LookupErrorAD(f"Domain not found: {name}")

    def dns_lookup(
        self, name: str, record_type: str
    ) -> list[DnsRecord]:
        normalized = normalize_dns_name(name)
        kind = record_type.upper()
        return sorted(
            (
                record
                for (record_name, record_kind), record
                in self.dns_records.items()
                if record_name == normalized and record_kind == kind
            ),
            key=lambda record: (record.priority, record.value),
        )

    def resolve_srv(
        self, domain_name: str, service: str = "ldap", protocol: str = "tcp"
    ) -> list[DnsRecord]:
        domain = normalize_dns_name(domain_name)
        service = service.casefold()
        protocol = protocol.casefold()
        if service not in {"ldap", "kerberos"}:
            raise ValidationError("Unsupported directory service.")
        if protocol not in {"tcp", "udp"}:
            raise ValidationError("Unsupported transport protocol.")

        query = f"_{service}._{protocol}.{domain}"
        return self.dns_lookup(query, "SRV")

    def can_authenticate(
        self, source_domain: str, target_domain: str
    ) -> bool:
        """Evaluate simplified trust reachability, not real authentication."""
        source = normalize_dns_name(source_domain)
        target = normalize_dns_name(target_domain)

        if source == target:
            return True

        source_obj = self.find_domain(source)
        target_obj = self.find_domain(target)

        # Domains within the same forest have an implicit trust relationship
        # in AD DS. Real authentication still requires working DCs and policy.
        if source_obj.forest_name == target_obj.forest_name:
            return True

        source_forest = source_obj.forest_name
        target_forest = target_obj.forest_name

        # Forest trusts are evaluated as directed edges. A bidirectional
        # trust grants reachability in both directions.
        graph: dict[str, set[str]] = {}
        for trust in self.trusts:
            if not trust.enabled:
                continue
            if trust.scope != TrustScope.FOREST:
                continue

            graph.setdefault(trust.source_forest, set())
            graph.setdefault(trust.target_forest, set())

            if trust.direction in {
                TrustDirection.OUTBOUND,
                TrustDirection.BIDIRECTIONAL,
            }:
                graph[trust.source_forest].add(trust.target_forest)

            if trust.direction in {
                TrustDirection.INBOUND,
                TrustDirection.BIDIRECTIONAL,
            }:
                graph[trust.target_forest].add(trust.source_forest)

            # Non-transitive trusts are direct links only.
            if not trust.transitive:
                graph[trust.source_forest].discard(trust.target_forest)
                graph[trust.target_forest].discard(trust.source_forest)
                if trust.direction in {
                    TrustDirection.OUTBOUND,
                    TrustDirection.BIDIRECTIONAL,
                }:
                    graph[trust.source_forest].add(target_forest)
                if trust.direction in {
                    TrustDirection.INBOUND,
                    TrustDirection.BIDIRECTIONAL,
                }:
                    graph[trust.target_forest].add(source_forest)

        visited = {source_forest}
        queue = [source_forest]
        while queue:
            current = queue.pop(0)
            for neighbor in graph.get(current, set()):
                if neighbor == target_forest:
                    return True
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        return False


def build_example_environment() -> DirectoryEnvironment:
    environment = DirectoryEnvironment()

    corp = Forest("corp.example.com")
    corp.add_domain(Domain("corp.example.com", "corp.example.com"))
    corp.add_domain(
        Domain(
            "engineering.corp.example.com",
            "corp.example.com",
            "corp.example.com",
        )
    )
    corp.add_domain(
        Domain(
            "research.corp.example.com",
            "corp.example.com",
            "corp.example.com",
        )
    )

    corp.domains["corp.example.com"].add_object(
        DirectoryObject(
            "DC=corp,DC=example,DC=com",
            "domain",
            {"dc": "corp"},
        )
    )
    corp.domains["engineering.corp.example.com"].add_object(
        DirectoryObject(
            "CN=Riya Sharma,OU=Engineering,DC=engineering,"
            "DC=corp,DC=example,DC=com",
            "user",
            {
                "cn": "Riya Sharma",
                "sAMAccountName": "riya.sharma",
                "department": "Engineering",
                "mail": "riya.sharma@corp.example.com",
            },
        )
    )
    corp.domains["engineering.corp.example.com"].add_object(
        DirectoryObject(
            "CN=Build Server,OU=Computers,DC=engineering,"
            "DC=corp,DC=example,DC=com",
            "computer",
            {
                "cn": "Build Server",
                "dNSHostName": "build01.engineering.corp.example.com",
            },
        )
    )
    corp.domains["research.corp.example.com"].add_object(
        DirectoryObject(
            "CN=Quantum Lab,OU=Groups,DC=research,DC=corp,"
            "DC=example,DC=com",
            "group",
            {
                "cn": "Quantum Lab",
                "description": "Research computing access group",
            },
        )
    )
    environment.add_forest(corp)

    partner = Forest("partner.example.net")
    partner.add_domain(Domain("partner.example.net", "partner.example.net"))
    partner.domains["partner.example.net"].add_object(
        DirectoryObject(
            "CN=External Analyst,OU=Users,DC=partner,DC=example,DC=net",
            "user",
            {
                "cn": "External Analyst",
                "sAMAccountName": "analyst",
                "department": "Operations",
            },
        )
    )
    environment.add_forest(partner)

    environment.add_trust(
        Trust(
            "corp.example.com",
            "partner.example.net",
            TrustDirection.BIDIRECTIONAL,
            TrustScope.FOREST,
            transitive=True,
        )
    )

    environment.add_dns_record(
        DnsRecord(
            "dc01.corp.example.com",
            "A",
            "10.20.0.10",
        )
    )
    environment.add_dns_record(
        DnsRecord(
            "_ldap._tcp.corp.example.com",
            "SRV",
            "dc01.corp.example.com.",
            priority=0,
            port=389,
        )
    )
    environment.add_dns_record(
        DnsRecord(
            "_kerberos._tcp.corp.example.com",
            "SRV",
            "dc01.corp.example.com.",
            priority=0,
            port=88,
        )
    )
    environment.add_dns_record(
        DnsRecord(
            "dc01.partner.example.net",
            "A",
            "10.40.0.10",
        )
    )
    environment.add_dns_record(
        DnsRecord(
            "_ldap._tcp.partner.example.net",
            "SRV",
            "dc01.partner.example.net.",
            priority=0,
            port=389,
        )
    )
    return environment


def ldap_filter_escape(value: str) -> str:
    """Escape RFC 4515 filter metacharacters to prevent filter injection."""
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(char, char) for char in value)


def demonstrate_ldap_filter_safety() -> None:
    supplied = "riya*)(objectClass=*)"
    safe = ldap_filter_escape(supplied)
    print("LDAP filter input:", supplied)
    print("Escaped LDAP assertion value:", safe)
    print("Constructed filter:", f"(sAMAccountName={safe})")


def run_demonstration() -> None:
    environment = build_example_environment()

    print("=== Forest and Domain Architecture ===")
    for forest in environment.forests.values():
        print(json.dumps(forest.describe(), indent=2))

    print("\n=== LDAP Directory Search ===")
    engineering = environment.find_domain(
        "engineering.corp.example.com"
    )
    print("Search base:", engineering.ldap_base_dn())
    for obj in engineering.search(
        object_class="user",
        attribute_name="department",
        attribute_value="Engineering",
    ):
        print(
            json.dumps(
                {
                    "dn": obj.distinguished_name,
                    "class": obj.object_class,
                    "attributes": obj.attributes,
                },
                indent=2,
            )
        )

    print("\n=== DNS Service Discovery ===")
    for service in ("ldap", "kerberos"):
        for record in environment.resolve_srv("corp.example.com", service):
            print(
                f"{record.name} -> {record.value} "
                f"port={record.port} priority={record.priority}"
            )

    print("\n=== Trust Reachability ===")
    scenarios = [
        (
            "engineering.corp.example.com",
            "research.corp.example.com",
        ),
        ("corp.example.com", "partner.example.net"),
    ]
    for source, target in scenarios:
        print(
            f"{source} -> {target}: "
            f"{environment.can_authenticate(source, target)}"
        )

    print("\n=== LDAP Filter Escaping ===")
    demonstrate_ldap_filter_safety()

    print("\n=== Operational Failure Cases ===")
    try:
        environment.find_domain("missing.example.org")
    except LookupErrorAD as exc:
        print("Expected lookup failure:", exc)

    try:
        environment.add_dns_record(
            DnsRecord("dc01.corp.example.com", "A", "10.20.0.11")
        )
    except ValidationError as exc:
        print("Expected duplicate DNS record failure:", exc)

    try:
        normalize_dns_name("invalid..example.com")
    except ValidationError as exc:
        print("Expected DNS validation failure:", exc)


if __name__ == "__main__":
    run_demonstration()
