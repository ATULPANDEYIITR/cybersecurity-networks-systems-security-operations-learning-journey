#!/usr/bin/env python3
"""
Threat Intelligence Management and Analysis System

Implements:
- Strategic, operational, and tactical intelligence
- Threat intelligence feed ingestion
- Indicator of Compromise (IOC) normalization
- STIX-inspired indicator representation
- Threat actor and campaign context
- Confidence and severity scoring
- TLP information-sharing restrictions
- Indicator expiration and deduplication
- Threat correlation and prioritization
- Intelligence reporting
- JSON persistence
- Validation and automated tests

Python 3.10+
Standard library only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import unittest

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

logger = logging.getLogger("threat_intelligence")


class IntelligenceType(Enum):
    STRATEGIC = "strategic"
    OPERATIONAL = "operational"
    TACTICAL = "tactical"


class IndicatorType(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


class TLP(Enum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"


class ThreatSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IntelligenceStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"
    REVOKED = "revoked"


@dataclass(frozen=True)
class ThreatActor:
    actor_id: str
    name: str
    description: str
    motivation: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class ThreatCampaign:
    campaign_id: str
    name: str
    actor_id: str
    objectives: tuple[str, ...]
    targeted_sectors: tuple[str, ...]


@dataclass
class ThreatIndicator:
    value: str
    indicator_type: IndicatorType
    source: str
    confidence: int
    severity: ThreatSeverity
    tlp: TLP
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime
    intelligence_type: IntelligenceType
    description: str = ""
    actor_id: Optional[str] = None
    campaign_id: Optional[str] = None
    tags: set[str] = field(default_factory=set)
    status: IntelligenceStatus = IntelligenceStatus.ACTIVE
    references: list[str] = field(default_factory=list)
    indicator_id: str = field(init=False)

    def __post_init__(self):
        self.value = normalize_indicator(
            self.value, self.indicator_type
        )

        if not 0 <= self.confidence <= 100:
            raise ValueError("Confidence must be between 0 and 100.")

        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen.")

        if self.expires_at <= self.first_seen:
            raise ValueError("Expiration must follow first_seen.")

        if not self.source.strip():
            raise ValueError("Source cannot be empty.")

        if self.actor_id == "":
            raise ValueError("Actor ID cannot be empty.")

        self.indicator_id = hashlib.sha256(
            f"{self.indicator_type.value}:{self.value}".encode()
        ).hexdigest()[:24]

    def is_expired(self, current_time: datetime) -> bool:
        return current_time >= self.expires_at

    def risk_score(self) -> float:
        """
        Deterministic prioritization score.

        Confidence contributes 40%.
        Severity contributes 40%.
        Intelligence recency contributes 20%.
        """
        now = datetime.now(timezone.utc)

        age_hours = max(
            0.0,
            (now - self.last_seen).total_seconds() / 3600
        )

        recency = max(0.0, 100.0 - age_hours / 24 * 5)

        score = (
            self.confidence * 0.4
            + self.severity.value * 25 * 0.4
            + recency * 0.2
        )

        if self.status != IntelligenceStatus.ACTIVE:
            return 0.0

        if self.is_expired(now):
            return 0.0

        return round(min(score, 100.0), 2)


def normalize_indicator(
    value: str,
    indicator_type: IndicatorType
) -> str:

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Indicator cannot be empty.")

    value = value.strip()

    if len(value) > 2048:
        raise ValueError("Indicator exceeds maximum length.")

    if indicator_type in (
        IndicatorType.IPV4,
        IndicatorType.IPV6
    ):
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Invalid IP address.") from exc

        expected_version = (
            4 if indicator_type == IndicatorType.IPV4 else 6
        )

        if address.version != expected_version:
            raise ValueError("IP version does not match indicator type.")

        return str(address)

    if indicator_type == IndicatorType.DOMAIN:
        domain = value.rstrip(".").lower()

        if len(domain) > 253:
            raise ValueError("Domain is too long.")

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Invalid internationalized domain.") from exc

        labels = domain.split(".")

        if len(labels) < 2 or any(
            not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                label
            )
            for label in labels
        ):
            raise ValueError("Invalid domain name.")

        return domain

    if indicator_type in (
        IndicatorType.MD5,
        IndicatorType.SHA1,
        IndicatorType.SHA256
    ):
        lengths = {
            IndicatorType.MD5: 32,
            IndicatorType.SHA1: 40,
            IndicatorType.SHA256: 64
        }

        if not re.fullmatch(
            rf"[0-9a-fA-F]{{{lengths[indicator_type]}}}",
            value
        ):
            raise ValueError("Invalid cryptographic hash.")

        return value.lower()

    if indicator_type == IndicatorType.EMAIL:
        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            value
        ):
            raise ValueError("Invalid email indicator.")

        local, domain = value.rsplit("@", 1)
        return f"{local}@{normalize_indicator(domain, IndicatorType.DOMAIN)}"

    if indicator_type == IndicatorType.URL:
        from urllib.parse import urlsplit, urlunsplit

        if any(ord(char) < 32 for char in value):
            raise ValueError("URL contains control characters.")

        parsed = urlsplit(value)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS indicators are supported.")

        if not parsed.hostname:
            raise ValueError("URL hostname is missing.")

        try:
            hostname = normalize_indicator(
                parsed.hostname,
                IndicatorType.IPV4 if
                re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parsed.hostname)
                else IndicatorType.DOMAIN
            )
        except ValueError:
            try:
                hostname = str(ipaddress.ip_address(parsed.hostname))
            except ValueError:
                raise

        netloc = hostname

        if parsed.port:
            netloc = f"{hostname}:{parsed.port}"

        if parsed.username or parsed.password:
            raise ValueError("URLs containing credentials are prohibited.")

        return urlunsplit((
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            ""
        ))

    raise ValueError("Unsupported indicator type.")


class SharingPolicy:
    """Controls disclosure according to Traffic Light Protocol labels."""

    @staticmethod
    def can_share(
        classification: TLP,
        recipient_group: str
    ) -> bool:

        groups = {
            "public",
            "community",
            "organization",
            "designated_group",
            "internal"
        }

        if recipient_group not in groups:
            return False

        rules = {
            TLP.CLEAR: groups,
            TLP.GREEN: {
                "community",
                "organization",
                "designated_group",
                "internal"
            },
            TLP.AMBER: {
                "organization",
                "designated_group",
                "internal"
            },
            TLP.AMBER_STRICT: {
                "designated_group",
                "internal"
            },
            TLP.RED: set()
        }

        return recipient_group in rules[classification]


class ThreatIntelligencePlatform:

    def __init__(self):
        self.indicators: dict[str, ThreatIndicator] = {}
        self.actors: dict[str, ThreatActor] = {}
        self.campaigns: dict[str, ThreatCampaign] = {}
        self.feed_history: list[dict] = []

    def register_actor(self, actor: ThreatActor):
        if actor.actor_id in self.actors:
            raise ValueError("Threat actor already exists.")

        self.actors[actor.actor_id] = actor

    def register_campaign(self, campaign: ThreatCampaign):
        if campaign.campaign_id in self.campaigns:
            raise ValueError("Campaign already exists.")

        if campaign.actor_id not in self.actors:
            raise ValueError("Campaign references an unknown actor.")

        self.campaigns[campaign.campaign_id] = campaign

    def ingest(self, indicator: ThreatIndicator) -> str:

        if indicator.actor_id and indicator.actor_id not in self.actors:
            raise ValueError("Unknown threat actor.")

        if (
            indicator.campaign_id
            and indicator.campaign_id not in self.campaigns
        ):
            raise ValueError("Unknown threat campaign.")

        existing = self.indicators.get(indicator.indicator_id)

        if existing:
            # Merge evidence without replacing the original identity.
            existing.confidence = max(
                existing.confidence,
                indicator.confidence
            )

            existing.severity = max(
                existing.severity,
                indicator.severity,
                key=lambda item: item.value
            )

            existing.last_seen = max(
                existing.last_seen,
                indicator.last_seen
            )

            existing.expires_at = max(
                existing.expires_at,
                indicator.expires_at
            )

            existing.tags.update(indicator.tags)

            if indicator.source not in existing.references:
                existing.references.append(indicator.source)

            return existing.indicator_id

        self.indicators[indicator.indicator_id] = indicator
        return indicator.indicator_id

    def ingest_feed(self, records: list[dict]) -> dict:

        successful = 0
        rejected = []

        for index, record in enumerate(records):

            try:
                indicator = ThreatIndicator(
                    value=record["value"],
                    indicator_type=IndicatorType(record["type"]),
                    source=record["source"],
                    confidence=int(record["confidence"]),
                    severity=ThreatSeverity[
                        record["severity"].upper()
                    ],
                    tlp=TLP(record.get("tlp", "amber")),
                    first_seen=datetime.fromisoformat(
                        record["first_seen"]
                    ),
                    last_seen=datetime.fromisoformat(
                        record["last_seen"]
                    ),
                    expires_at=datetime.fromisoformat(
                        record["expires_at"]
                    ),
                    intelligence_type=IntelligenceType(
                        record["intelligence_type"]
                    ),
                    description=record.get("description", ""),
                    actor_id=record.get("actor_id"),
                    campaign_id=record.get("campaign_id"),
                    tags=set(record.get("tags", []))
                )

                self.ingest(indicator)
                successful += 1

            except (ValueError, KeyError, TypeError) as exc:
                rejected.append({
                    "record": index,
                    "error": str(exc)
                })

        result = {
            "received": len(records),
            "accepted": successful,
            "rejected": rejected,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self.feed_history.append(result)
        return result

    def search(
        self,
        indicator_type: Optional[IndicatorType] = None,
        tag: Optional[str] = None,
        intelligence_type: Optional[IntelligenceType] = None,
        active_only: bool = True
    ) -> list[ThreatIndicator]:

        now = datetime.now(timezone.utc)

        results = []

        for indicator in self.indicators.values():

            if active_only and (
                indicator.status != IntelligenceStatus.ACTIVE
                or indicator.is_expired(now)
            ):
                continue

            if (
                indicator_type
                and indicator.indicator_type != indicator_type
            ):
                continue

            if tag and tag not in indicator.tags:
                continue

            if (
                intelligence_type
                and indicator.intelligence_type != intelligence_type
            ):
                continue

            results.append(indicator)

        return sorted(
            results,
            key=lambda item: item.risk_score(),
            reverse=True
        )

    def update_status(
        self,
        indicator_id: str,
        status: IntelligenceStatus
    ):
        indicator = self.indicators.get(indicator_id)

        if not indicator:
            raise KeyError("Indicator not found.")

        indicator.status = status

    def expire_indicators(self) -> int:

        now = datetime.now(timezone.utc)
        count = 0

        for indicator in self.indicators.values():

            if (
                indicator.status == IntelligenceStatus.ACTIVE
                and indicator.is_expired(now)
            ):
                indicator.status = IntelligenceStatus.EXPIRED
                count += 1

        return count

    def correlate_campaign(
        self,
        campaign_id: str
    ) -> list[ThreatIndicator]:

        if campaign_id not in self.campaigns:
            raise KeyError("Unknown campaign.")

        return [
            indicator
            for indicator in self.search(active_only=False)
            if indicator.campaign_id == campaign_id
        ]

    def evaluate_observable(self, value: str) -> list[dict]:
        """Match a normalized observable against known indicators."""

        matches = []

        for indicator in self.search():

            if value == indicator.value:
                matches.append({
                    "indicator_id": indicator.indicator_id,
                    "type": indicator.indicator_type.value,
                    "confidence": indicator.confidence,
                    "severity": indicator.severity.name,
                    "risk_score": indicator.risk_score(),
                    "source": indicator.source,
                    "tlp": indicator.tlp.value
                })

        return matches

    def intelligence_report(self) -> dict:

        active = self.search()

        distribution = {
            category.value: sum(
                item.intelligence_type == category
                for item in active
            )
            for category in IntelligenceType
        }

        severity = {
            category.name: sum(
                item.severity == category
                for item in active
            )
            for category in ThreatSeverity
        }

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_indicators": len(self.indicators),
            "active_indicators": len(active),
            "threat_actors": len(self.actors),
            "campaigns": len(self.campaigns),
            "intelligence_distribution": distribution,
            "severity_distribution": severity,
            "highest_priority": [
                {
                    "value": item.value,
                    "type": item.indicator_type.value,
                    "risk_score": item.risk_score(),
                    "source": item.source
                }
                for item in active[:10]
            ]
        }

    def save(self, filepath: str):

        data = {
            "indicators": [],
            "actors": [
                asdict(actor)
                for actor in self.actors.values()
            ],
            "campaigns": [
                asdict(campaign)
                for campaign in self.campaigns.values()
            ]
        }

        for indicator in self.indicators.values():

            record = {
                "value": indicator.value,
                "indicator_type": indicator.indicator_type.value,
                "source": indicator.source,
                "confidence": indicator.confidence,
                "severity": indicator.severity.name,
                "tlp": indicator.tlp.value,
                "first_seen": indicator.first_seen.isoformat(),
                "last_seen": indicator.last_seen.isoformat(),
                "expires_at": indicator.expires_at.isoformat(),
                "intelligence_type": indicator.intelligence_type.value,
                "description": indicator.description,
                "actor_id": indicator.actor_id,
                "campaign_id": indicator.campaign_id,
                "tags": sorted(indicator.tags),
                "status": indicator.status.value,
                "references": indicator.references
            }

            data["indicators"].append(record)

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        temporary = path.with_suffix(path.suffix + ".tmp")

        temporary.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8"
        )

        temporary.replace(path)

    def load(self, filepath: str):

        data = json.loads(
            Path(filepath).read_text(encoding="utf-8")
        )

        for actor_data in data.get("actors", []):

            actor_data["aliases"] = tuple(
                actor_data.get("aliases", [])
            )

            self.register_actor(ThreatActor(**actor_data))

        for campaign_data in data.get("campaigns", []):

            campaign_data["objectives"] = tuple(
                campaign_data["objectives"]
            )

            campaign_data["targeted_sectors"] = tuple(
                campaign_data["targeted_sectors"]
            )

            self.register_campaign(
                ThreatCampaign(**campaign_data)
            )

        for record in data.get("indicators", []):

            indicator = ThreatIndicator(
                value=record["value"],
                indicator_type=IndicatorType(
                    record["indicator_type"]
                ),
                source=record["source"],
                confidence=record["confidence"],
                severity=ThreatSeverity[record["severity"]],
                tlp=TLP(record["tlp"]),
                first_seen=datetime.fromisoformat(
                    record["first_seen"]
                ),
                last_seen=datetime.fromisoformat(
                    record["last_seen"]
                ),
                expires_at=datetime.fromisoformat(
                    record["expires_at"]
                ),
                intelligence_type=IntelligenceType(
                    record["intelligence_type"]
                ),
                description=record["description"],
                actor_id=record["actor_id"],
                campaign_id=record["campaign_id"],
                tags=set(record["tags"]),
                status=IntelligenceStatus(record["status"]),
                references=record["references"]
            )

            self.ingest(indicator)


def create_sample_platform() -> ThreatIntelligencePlatform:

    platform = ThreatIntelligencePlatform()

    actor = ThreatActor(
        actor_id="ACT-001",
        name="Example Advanced Persistent Threat",
        description="A simulated espionage-oriented threat group.",
        motivation="Espionage",
        aliases=("EXAMPLE-APT",)
    )

    platform.register_actor(actor)

    campaign = ThreatCampaign(
        campaign_id="CMP-001",
        name="Operation Northern Gateway",
        actor_id="ACT-001",
        objectives=("Credential theft", "Data exfiltration"),
        targeted_sectors=("Government", "Energy")
    )

    platform.register_campaign(campaign)

    now = datetime.now(timezone.utc)

    records = [
        {
            "value": "203.0.113.25",
            "type": "ipv4",
            "source": "Example-TI-Feed",
            "confidence": 95,
            "severity": "critical",
            "tlp": "amber",
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "intelligence_type": "tactical",
            "description": "Simulated command-and-control address.",
            "actor_id": "ACT-001",
            "campaign_id": "CMP-001",
            "tags": ["c2", "malware", "government"]
        },
        {
            "value": "malicious-example.org",
            "type": "domain",
            "source": "OSINT-Feed",
            "confidence": 85,
            "severity": "high",
            "tlp": "green",
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
            "expires_at": (now + timedelta(days=15)).isoformat(),
            "intelligence_type": "operational",
            "description": "Simulated phishing infrastructure.",
            "actor_id": "ACT-001",
            "campaign_id": "CMP-001",
            "tags": ["phishing", "infrastructure"]
        }
    ]

    platform.ingest_feed(records)

    return platform


class ThreatIntelligenceTests(unittest.TestCase):

    def test_ip_normalization(self):
        self.assertEqual(
            normalize_indicator("203.0.113.25", IndicatorType.IPV4),
            "203.0.113.25"
        )

    def test_invalid_ip(self):
        with self.assertRaises(ValueError):
            normalize_indicator("999.999.999.999", IndicatorType.IPV4)

    def test_hash_normalization(self):
        self.assertEqual(
            normalize_indicator("A" * 64, IndicatorType.SHA256),
            "a" * 64
        )

    def test_tlp_restriction(self):
        self.assertFalse(
            SharingPolicy.can_share(TLP.RED, "public")
        )

    def test_tlp_green(self):
        self.assertTrue(
            SharingPolicy.can_share(TLP.GREEN, "community")
        )

    def test_deduplication(self):
        platform = create_sample_platform()
        self.assertEqual(len(platform.indicators), 2)

        indicator = next(iter(platform.indicators.values()))
        original_count = len(platform.indicators)

        platform.ingest(indicator)

        self.assertEqual(
            len(platform.indicators),
            original_count
        )

    def test_expiration(self):
        platform = create_sample_platform()
        self.assertEqual(platform.expire_indicators(), 0)

    def test_unknown_actor(self):
        platform = ThreatIntelligencePlatform()
        now = datetime.now(timezone.utc)

        indicator = ThreatIndicator(
            value="203.0.113.40",
            indicator_type=IndicatorType.IPV4,
            source="test",
            confidence=80,
            severity=ThreatSeverity.HIGH,
            tlp=TLP.AMBER,
            first_seen=now,
            last_seen=now,
            expires_at=now + timedelta(days=1),
            intelligence_type=IntelligenceType.TACTICAL,
            actor_id="UNKNOWN"
        )

        with self.assertRaises(ValueError):
            platform.ingest(indicator)


def main():

    platform = create_sample_platform()

    print("\nTHREAT INTELLIGENCE PLATFORM")
    print("=" * 55)

    print("\nFEED INGESTION")
    print(json.dumps(
        platform.feed_history,
        indent=2
    ))

    print("\nACTIVE INDICATORS")

    for indicator in platform.search():
        print({
            "value": indicator.value,
            "type": indicator.indicator_type.value,
            "severity": indicator.severity.name,
            "confidence": indicator.confidence,
            "risk_score": indicator.risk_score()
        })

    print("\nCAMPAIGN CORRELATION")

    for indicator in platform.correlate_campaign("CMP-001"):
        print(indicator.value, indicator.description)

    print("\nOBSERVABLE EVALUATION")

    print(
        json.dumps(
            platform.evaluate_observable("203.0.113.25"),
            indent=2
        )
    )

    print("\nINTELLIGENCE REPORT")

    print(
        json.dumps(
            platform.intelligence_report(),
            indent=2
        )
    )

    print("\nTLP SHARING DECISION")

    print(
        SharingPolicy.can_share(
            TLP.AMBER,
            "organization"
        )
    )

    print("\nAUTOMATED TESTS")

    unittest.main(
        argv=["threat_intelligence.py"],
        exit=False
    )


if __name__ == "__main__":
    main()
