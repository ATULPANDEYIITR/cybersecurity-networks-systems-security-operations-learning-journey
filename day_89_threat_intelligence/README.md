# Threat Intelligence Management and Analysis Platform

## 1. Domain Overview

Threat intelligence is the collection, processing, analysis, validation, interpretation, and distribution of information about cyber threats.

It transforms raw security observations into actionable knowledge about threat actors, campaigns, infrastructure, vulnerabilities, malicious activity, and potential organizational impact.

The implementations in this project demonstrate a threat intelligence management platform using Python, JavaScript, C++17, Java 17, and PostgreSQL.

The platform models the intelligence lifecycle:

Collection → Validation → Normalization → Enrichment → Correlation → Analysis → Prioritization → Dissemination → Review

The implementations use simulated indicators and reserved example IP addresses and domains. They do not contact malicious infrastructure or perform active exploitation.

## 2. Intelligence Categories

Threat intelligence is divided into three complementary categories.

### 2.1 Strategic Threat Intelligence

Strategic intelligence provides a high-level understanding of the threat environment.

It supports organizational leadership, risk management, security planning, and resource allocation.

Typical information includes:

- Geopolitical developments affecting cybersecurity.
- Cybercrime and espionage trends.
- Threat activity affecting national infrastructure.
- Sector-specific exposure.
- Changes in attacker motivations.
- Long-term cybersecurity risks.
- Threat landscape assessments.

Example:

A strategic assessment identifies increasing cyber espionage risks against government and energy infrastructure.

The output is an analytical intelligence product containing executive summaries, key judgments, confidence assessments, and implications.

### 2.2 Operational Threat Intelligence

Operational intelligence explains how campaigns and threat operations are organized.

It connects threat actors, objectives, targeted sectors, infrastructure, and observed activities.

Typical information includes:

- Threat campaigns.
- Threat actor relationships.
- Operational objectives.
- Target selection.
- Attack timelines.
- Campaign infrastructure.
- Malware deployment patterns.
- Phishing and credential theft operations.

Example:

An intelligence analyst identifies a campaign targeting government organizations through credential theft and phishing infrastructure.

Campaign correlation connects the observed domains, IP addresses, threat actor attribution, and operational objectives.

### 2.3 Tactical Threat Intelligence

Tactical intelligence focuses on technical details associated with detecting and responding to malicious activity.

It primarily supports security operations centers, incident responders, threat hunters, and detection engineers.

Typical information includes:

- IP addresses.
- Domain names.
- URLs.
- File hashes.
- Email addresses.
- Network indicators.
- Malware characteristics.
- Detection signatures.
- Attack techniques.
- Observable infrastructure.

Example:

A security monitoring system detects communication with an IP address already present in its threat intelligence database.

The matching indicator provides confidence, severity, source, classification, and associated campaign information.

### 2.4 Distinctions

| Characteristic | Strategic | Operational | Tactical |
|---|---|---|---|
| Primary focus | Threat environment | Campaign activity | Technical evidence |
| Main audience | Leadership | Threat analysts | SOC and incident responders |
| Time horizon | Long-term | Medium-term | Immediate to short-term |
| Information | Trends and assessments | Actors and campaigns | IOCs and detection details |
| Main output | Strategic assessment | Campaign intelligence | Detection intelligence |
| Main purpose | Risk decisions | Operational planning | Threat detection |

These categories are complementary. Tactical indicators can support operational campaign analysis, which can contribute to strategic assessments.

## 3. Threat Intelligence Collection

Collection is the acquisition of threat-related information from external and internal sources.

### 3.1 Intelligence Sources

Common source categories include:

| Source | Information |
|---|---|
| OSINT | Publicly available threat information |
| Commercial feeds | Subscription-based indicators |
| Government intelligence | Government-distributed threat information |
| ISACs | Sector-specific threat intelligence |
| CERTs and CSIRTs | Incident and vulnerability intelligence |
| Internal SOC | Security events and observations |
| Honeypots | Observed attacker activity |
| Malware analysis | Malware behavior and indicators |
| Incident response | Evidence from security investigations |

Each source has different reliability, coverage, timeliness, and sharing restrictions.

A feed should not be considered trustworthy merely because it successfully delivers records.

Source reliability and individual indicator confidence must be assessed separately.

### 3.2 Feed Ingestion

The platform represents feeds using:

- Feed identifier.
- Source name.
- Feed format.
- Polling interval.
- Operational status.
- Last successful ingestion.
- Last failed ingestion.
- Accepted record count.
- Rejected record count.

The JavaScript implementation uses asynchronous feed providers and bounded concurrency.

Each feed is processed independently. A failed feed does not prevent other feeds from completing.

The Python implementation provides batch ingestion with record-level validation and rejection reporting.

The PostgreSQL implementation records ingestion runs and maintains acceptance statistics.

## 4. Indicators of Compromise

An Indicator of Compromise is an observable artifact that may indicate malicious or suspicious activity.

Indicators are evidence, not automatic proof of compromise.

### 4.1 Indicator Categories

| Indicator | Description |
|---|---|
| IPv4 | Internet Protocol version 4 address |
| IPv6 | Internet Protocol version 6 address |
| Domain | Domain name associated with activity |
| URL | Web resource associated with activity |
| MD5 | 128-bit file digest |
| SHA-1 | 160-bit file digest |
| SHA-256 | 256-bit file digest |
| Email | Email address associated with activity |

### 4.2 Indicator Lifecycle

An indicator progresses through a managed lifecycle:

Collection → Validation → Normalization → Deduplication → Enrichment → Publication → Monitoring → Expiration or Revocation

Important lifecycle states include:

| State | Meaning |
|---|---|
| Active | Indicator is eligible for current analysis |
| Expired | Indicator has passed its validity period |
| False Positive | Indicator has been determined to be incorrectly classified |
| Revoked | Indicator has been withdrawn |

An expired indicator should not automatically be interpreted as harmless. Expiration means that its validity period has ended, not that the historical observation has become false.

### 4.3 Normalization

Normalization converts equivalent representations into a consistent form.

Examples:

- Domain names are converted to lowercase.
- Trailing domain dots are removed.
- IPv4 addresses are checked for valid octets.
- Cryptographic hashes are converted to lowercase.
- Indicator types are validated before ingestion.

Normalization supports consistent searching and deduplication.

It is important to preserve the original source value when building a production platform because normalized values alone may not retain the original evidence representation.

### 4.4 Deduplication

Multiple intelligence feeds can report the same observable.

The platform identifies indicators through a deterministic combination of indicator type and normalized value.

When duplicate observations arrive, the implementations merge selected attributes:

- Highest confidence.
- Highest severity.
- Latest observation time.
- Latest expiration time.
- Additional tags.
- Source references.

Source provenance remains important because two sources reporting the same indicator provide different evidence from one source reporting it repeatedly.

The PostgreSQL implementation retains source-specific indicator records and supports cross-source duplicate analysis.

## 5. Threat Actors and Campaigns

### 5.1 Threat Actors

A threat actor is an individual, group, organization, or other entity responsible for malicious or potentially malicious activity.

Threat actor records may contain:

- Actor identifier.
- Name.
- Aliases.
- Motivation.
- Sophistication.
- Description.
- Associated campaigns.

Attribution is often uncertain. An observed indicator should not be treated as conclusive evidence of actor identity.

### 5.2 Threat Campaigns

A campaign is a coordinated collection of related malicious activities associated with an objective or operational effort.

Campaign information may include:

- Campaign identifier.
- Campaign name.
- Associated threat actor.
- Objectives.
- Targeted sectors.
- Activity period.
- Related indicators.

The relationship is:

Threat Actor → Campaign → Indicators → Observations

A single actor can participate in multiple campaigns, and multiple indicators can be associated with one campaign.

The Python, C++, and Java implementations validate campaign-to-actor relationships before accepting associated indicators.

The PostgreSQL implementation enforces relational references using foreign keys.

## 6. Confidence, Severity, and Risk Prioritization

These three concepts represent different analytical dimensions.

### 6.1 Confidence

Confidence describes the degree of belief that an intelligence assessment or indicator is accurate.

The implementations use a numerical scale from 0 to 100.

A higher confidence value represents stronger analytical confidence.

Confidence should consider:

- Source reliability.
- Evidence quality.
- Independent corroboration.
- Observation consistency.
- Analytical uncertainty.
- Attribution limitations.

Confidence is not the same as the likelihood of organizational compromise.

### 6.2 Severity

Severity represents the assessed seriousness of a threat.

The implementations use four levels:

| Severity | Value |
|---|---:|
| Low | 1 |
| Medium | 2 |
| High | 3 |
| Critical | 4 |

Severity should reflect potential consequences and operational relevance.

### 6.3 Risk Score

The implementations provide an illustrative prioritization formula:

Risk Score = (Confidence × 0.40) + (Severity Weight × 0.40) + (Recency × 0.20)

The recency component decreases as the time since the latest observation increases.

The resulting score is bounded between 0 and 100.

This formula is an engineering demonstration, not a calibrated cybersecurity risk model.

A production implementation should account for asset criticality, exposure, exploitability, observed activity, business impact, intelligence reliability, and uncertainty.

## 7. Threat Intelligence Sharing and TLP

The Traffic Light Protocol provides standardized labels for communicating information-sharing restrictions.

The implementations represent five classifications.

| Classification | Meaning |
|---|---|
| TLP:CLEAR | Information may be shared without restrictions based on the TLP label |
| TLP:GREEN | Sharing is permitted within the applicable community |
| TLP:AMBER | Sharing is restricted to the recipient's organization and authorized recipients |
| TLP:AMBER+STRICT | Sharing is restricted to the intended organization |
| TLP:RED | Information is restricted to the intended recipients |

TLP classification is not a measure of threat severity, confidence, or intelligence quality.

It is an information-sharing control.

The implementations model recipient groups and evaluate whether a particular classification permits sharing.

The Java and Python implementations expose explicit policy-evaluation functions.

The C++ implementation uses an independent rule-based policy engine.

The PostgreSQL implementation stores classification rules and sharing decisions in relational tables.

A production system must also authenticate recipients, enforce authorization, maintain audit records, and apply the applicable TLP specification.

## 8. Threat Intelligence Correlation

Correlation connects related intelligence records to identify meaningful relationships.

Examples include:

- Multiple indicators associated with one campaign.
- Multiple campaigns attributed to one actor.
- One domain observed by multiple intelligence sources.
- Indicators sharing common tags.
- Repeated observations across different feeds.
- Related indicators targeting the same sector.

### 8.1 Observable Matching

Observable matching compares normalized security telemetry with stored indicators.

Example:

A monitoring system receives an outbound network connection containing an IP address.

The observable is normalized and searched against active IPv4 indicators.

If a matching indicator exists, the platform returns:

- Indicator identifier.
- Indicator type.
- Confidence.
- Severity.
- Source.
- TLP classification.
- Risk score.

A match should initiate investigation or detection logic according to organizational policy. It should not automatically establish that an incident has occurred.

### 8.2 Campaign Correlation

Campaign correlation retrieves active indicators associated with a campaign.

This supports operational analysis by connecting technical evidence to campaign objectives and threat actor context.

The Python, C++, and Java implementations provide dedicated campaign-correlation operations.

## 9. Implementation Architecture

### 9.1 Python

The Python implementation provides a complete threat intelligence simulation.

Core components:

| Component | Responsibility |
|---|---|
| `ThreatActor` | Threat actor representation |
| `ThreatCampaign` | Campaign representation |
| `ThreatIndicator` | IOC validation and lifecycle |
| `SharingPolicy` | TLP policy evaluation |
| `ThreatIntelligencePlatform` | Collection and analysis |
| `ThreatIntelligenceTests` | Automated validation |

Important mechanisms:

- Dataclasses for domain modeling.
- Enums for controlled classification values.
- Dictionaries for indicator indexing.
- Sets for tags and deduplication.
- SHA-256-based deterministic identifiers.
- JSON persistence.
- Feed ingestion with record-level error isolation.
- Campaign correlation.
- Observable matching.
- Expiration processing.
- Unit tests and assertions.

The dictionary-based indicator lookup provides average constant-time access by indicator identifier.

Search operations require scanning the stored indicators and sorting the matching records.

### 9.2 JavaScript

The JavaScript implementation provides an asynchronous, event-driven intelligence engine.

Core components:

- `ThreatIndicator`
- `ThreatIntelligenceEngine`
- `SharingPolicy`
- `ThreatIntelError`

JavaScript-specific mechanisms include:

- Private class fields.
- `Map` for indicator and actor storage.
- `Set` for tags and source references.
- `EventEmitter` for lifecycle events.
- Promises and asynchronous feed ingestion.
- Bounded feed concurrency.
- Failure isolation.
- JSON persistence.

Important events include:

| Event | Meaning |
|---|---|
| `actor:registered` | Actor successfully registered |
| `campaign:registered` | Campaign registered |
| `indicator:ingested` | New indicator accepted |
| `indicator:updated` | Existing indicator enriched |
| `indicator:expired` | Indicator expired |
| `indicator:status-changed` | Lifecycle status changed |
| `feed:failed` | Feed processing failed |
| `feeds:completed` | Feed batch completed |

The event-driven design separates intelligence processing from downstream consumers.

For example, an event consumer can record an audit entry or initiate a separate notification workflow.

### 9.3 C++17

The C++ implementation emphasizes domain modeling and efficient in-memory processing.

Core components:

- `ThreatActor`
- `Campaign`
- `Indicator`
- `SharingPolicy`
- `ThreatIntelligenceEngine`

Important mechanisms:

- Strongly typed enumerations.
- Struct-based domain records.
- STL containers.
- `unordered_map` for indicator storage.
- `set` for tags and source references.
- `optional` search parameters.
- Exception-based validation.
- STL sorting algorithms.
- Campaign and observable correlation.

The implementation uses a standard-library hash function for in-process deterministic lookup keys.

That hash is not cryptographically secure and must not be treated as a persistent identifier across processes or platforms.

Production deployments should use a cryptographic digest such as SHA-256 when stable, collision-resistant identifiers are required.

### 9.4 Java 17

The Java implementation models an enterprise-oriented intelligence service.

Core components:

- `ThreatActor`
- `ThreatCampaign`
- `FeedRecord`
- `Indicator`
- `IndicatorNormalizer`
- `SharingPolicy`
- `ThreatIntelligenceService`
- `FeedProvider`

Java-specific mechanisms include:

- Records for immutable data transfer.
- Enums for domain classifications.
- Interfaces for feed abstraction.
- HashMap-based entity storage.
- HashSet-based indicator metadata.
- Stream-based filtering and aggregation.
- Custom runtime exceptions.
- Immutable collection boundaries.
- Explicit lifecycle state management.

The `FeedProvider` interface separates feed retrieval from indicator processing.

This allows independent feed implementations without changing the central intelligence service.

### 9.5 PostgreSQL

The PostgreSQL implementation models a relational threat intelligence database.

Main entities:

| Table | Responsibility |
|---|---|
| `organizations` | Participating organizations |
| `recipient_groups` | Intelligence-sharing groups |
| `intelligence_sources` | Intelligence source provenance |
| `intelligence_feeds` | Feed configuration |
| `feed_ingestion_runs` | Feed execution history |
| `threat_actors` | Threat actor information |
| `threat_actor_aliases` | Actor aliases |
| `threat_campaigns` | Campaign information |
| `targeted_sectors` | Targeted industry sectors |
| `campaign_targets` | Campaign-sector relationships |
| `intelligence_products` | Strategic and analytical reports |
| `indicators` | Indicator records |
| `indicator_tags` | Indicator classification tags |
| `indicator_references` | Supporting references |
| `indicator_observations` | Indicator observation history |
| `indicator_reviews` | Analyst validation |
| `tlp_sharing_rules` | Sharing permissions |
| `intelligence_sharing_events` | Sharing audit history |

The database uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Enumerated types.
- Partial indexes.
- GIN indexes for JSONB.
- Views.
- Stored procedures.
- Functions.
- Triggers.
- Transactions.
- Common relational queries.

The `active_indicator_risk` view calculates indicator prioritization.

The `campaign_intelligence` view aggregates campaign-related indicators.

The `ingest_indicator` procedure validates records and handles duplicate observations.

The sharing procedures record whether an intelligence disclosure is permitted.

## 10. Intelligence Workflow

The implemented architecture follows this workflow:

    Intelligence Sources
            |
            v
       Feed Ingestion
            |
            v
      Data Validation
            |
            v
       Normalization
            |
            v
       Deduplication
            |
            v
       IOC Repository
            |
            +-------------------+
            |                   |
            v                   v
       Threat Actors        Observations
            |                   |
            v                   |
       Campaigns <--------------+
            |
            v
      Threat Correlation
            |
            v
      Risk Prioritization
            |
            v
      Intelligence Analysis
            |
            v
      TLP Policy Evaluation
            |
            v
       Dissemination
            |
            v
      Audit and Monitoring

The workflow distinguishes raw intelligence collection from analytical assessment and controlled dissemination.

## 11. Validation and Failure Handling

Threat intelligence systems must prevent invalid information from entering analytical workflows.

The implementations validate:

- Missing indicators.
- Unsupported indicator types.
- Invalid IP addresses.
- Invalid domains.
- Incorrect hash lengths.
- Confidence outside the accepted range.
- Invalid timestamps.
- Missing source names.
- Unknown actors.
- Unknown campaigns.
- Invalid TLP values.
- Invalid recipient groups.
- Expired indicators.

Feed processing failures are recorded separately from individual record validation failures.

This distinction is important because a network connection failure, malformed feed, invalid indicator, and analytical rejection are different operational events.

## 12. Data Quality and Intelligence Provenance

Provenance identifies where intelligence originated and how it was obtained.

A reliable intelligence record should preserve:

- Original source.
- Source identifier.
- Feed identifier.
- Observation timestamp.
- Collection timestamp.
- Confidence.
- Classification.
- Supporting references.
- Review history.
- Expiration information.

Multiple sources may independently report the same indicator.

Cross-source agreement can strengthen an assessment, but repeated records should not automatically be treated as independent corroboration.

Source independence and the quality of underlying evidence must be considered.

## 13. Security and Governance Considerations

A production threat intelligence platform requires controls beyond the demonstration implementations.

### Access Control

Apply role-based or attribute-based access controls.

Typical roles include:

- Intelligence analyst.
- Threat hunter.
- SOC analyst.
- Intelligence administrator.
- Security leadership.
- External sharing recipient.

### Data Protection

Protect:

- Intelligence feeds.
- API credentials.
- Source configuration.
- Internal threat observations.
- Restricted intelligence products.
- Sharing records.

Use encrypted transport, appropriate encryption at rest, secret management, and access auditing.

### Feed Security

Feed ingestion should include:

- TLS certificate validation.
- Authentication.
- Feed signature verification where available.
- Input-size restrictions.
- Rate limiting.
- Timeout handling.
- Schema validation.
- Malformed-record isolation.
- Replay protection where applicable.

### Information Sharing

TLP restrictions must be enforced at the point of disclosure.

Merely storing a TLP label does not prevent unauthorized sharing.

Production authorization should evaluate the authenticated recipient, applicable organizational policy, data classification, and sharing restrictions.

### Indicator Safety

An indicator may be outdated, inaccurate, spoofed, or associated with legitimate shared infrastructure.

Automated blocking decisions should therefore consider contextual evidence and operational consequences.

## 14. Performance Considerations

The implementations use in-memory indexing for efficient identifier retrieval.

| Operation | Expected Complexity |
|---|---|
| Indicator lookup by ID | Average O(1) |
| Actor lookup | Average O(1) |
| Campaign lookup | Average O(1) |
| Indicator insertion | Average O(1) |
| Full indicator search | O(n) |
| Search result sorting | O(n log n) |
| Campaign correlation | O(n) |
| Observable matching | O(n) in the supplied in-memory models |
| Tag membership | Average O(1) |

The PostgreSQL implementation adds indexes for:

- Active indicator expiration.
- Campaign relationships.
- Threat actor relationships.
- Severity and confidence.
- Intelligence categories.
- Observable matching.
- Observation timestamps.
- Feed execution history.

For large deployments, additional architectural requirements include:

- Partitioning observation tables by time.
- Retention policies.
- Incremental feed processing.
- Distributed caching.
- Asynchronous message processing.
- Search indexes for high-volume observables.
- Database connection pooling.
- Workload isolation.
- Monitoring and alerting.

## 15. Limitations and Engineering Boundaries

The implementations demonstrate core threat intelligence mechanisms but are not complete commercial threat intelligence platforms.

Important limitations include:

- The risk formula is illustrative and not empirically calibrated.
- Sample threat actor and campaign records are fictional.
- Feed providers use simulated records.
- There is no live commercial or government feed integration.
- STIX objects are not fully implemented.
- TAXII transport is not implemented.
- Malware analysis is not performed.
- No real-time SIEM integration is included.
- No automated incident response is performed.
- The JavaScript IPv6 validation is intentionally limited and should be replaced with a complete IP-address parser.
- The C++ hash-based identifier is suitable only for demonstration lookup.
- The Python persistence model does not provide concurrent multi-user transaction management.
- The SQL domain validation and normalization functions are illustrative rather than complete implementations of every relevant Internet naming standard.
- Database authorization, application authentication, encryption, and operational deployment must be configured separately.

The system should therefore be treated as an educational reference implementation of threat intelligence collection, analysis, correlation, governance, and storage.

## 16. Execution Requirements

| Implementation | Runtime | External Dependencies |
|---|---|---|
| Python | Python 3.10+ | None |
| JavaScript | Node.js 18+ | None |
| C++17 | C++17 compiler | None |
| Java | JDK 17 | None |
| PostgreSQL | PostgreSQL 15+ | pgcrypto extension |

### Python

Save as `threat_intelligence.py`.

Execute:

`python threat_intelligence.py`

The program runs the sample intelligence workflow and its automated tests.

### JavaScript

Save as `threat-intelligence.js`.

Execute:

`node threat-intelligence.js`

The program processes asynchronous feeds, emits events, produces a report, and persists indicator records.

### C++17

Save as `threat_intelligence.cpp`.

Compile:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic threat_intelligence.cpp -o threat_intelligence`

Execute:

`./threat_intelligence`

### Java 17

Save as `ThreatIntelligencePlatform.java`.

Compile:

`javac ThreatIntelligencePlatform.java`

Execute:

`java ThreatIntelligencePlatform`

### PostgreSQL

Save as `threat_intelligence.sql`.

Execute:

`psql -U postgres -d postgres -f threat_intelligence.sql`

The database script creates the `threat_intel` schema, relational entities, indexes, validation functions, ingestion procedures, sharing policies, sample records, and analytical queries.
