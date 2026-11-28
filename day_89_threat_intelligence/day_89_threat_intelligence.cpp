#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

enum class IntelligenceType {
    Strategic,
    Operational,
    Tactical
};

enum class IndicatorType {
    IPv4,
    Domain,
    SHA256
};

enum class Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

enum class TLP {
    Clear,
    Green,
    Amber,
    AmberStrict,
    Red
};

enum class IndicatorStatus {
    Active,
    Expired,
    FalsePositive,
    Revoked
};

enum class BranchDecision {
    Allow,
    Reject
};

string toString(IntelligenceType type) {
    switch (type) {
        case IntelligenceType::Strategic: return "Strategic";
        case IntelligenceType::Operational: return "Operational";
        case IntelligenceType::Tactical: return "Tactical";
    }
    throw invalid_argument("Unknown intelligence type.");
}

string toString(Severity severity) {
    switch (severity) {
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    throw invalid_argument("Unknown severity.");
}

string toString(TLP tlp) {
    switch (tlp) {
        case TLP::Clear: return "CLEAR";
        case TLP::Green: return "GREEN";
        case TLP::Amber: return "AMBER";
        case TLP::AmberStrict: return "AMBER+STRICT";
        case TLP::Red: return "RED";
    }
    throw invalid_argument("Unknown TLP.");
}

string normalizeDomain(string value) {

    transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) {
            return static_cast<char>(tolower(c));
        }
    );

    if (!value.empty() && value.back() == '.') {
        value.pop_back();
    }

    if (value.size() > 253) {
        throw invalid_argument("Domain exceeds maximum length.");
    }

    static const regex domainPattern(
        R"(^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$)"
    );

    if (!regex_match(value, domainPattern)) {
        throw invalid_argument("Invalid domain.");
    }

    return value;
}

string normalizeIPv4(const string& value) {

    stringstream stream(value);
    string part;
    vector<int> octets;

    while (getline(stream, part, '.')) {

        if (part.empty() || part.size() > 3) {
            throw invalid_argument("Invalid IPv4 address.");
        }

        if (!all_of(
            part.begin(),
            part.end(),
            [](unsigned char c) { return isdigit(c); }
        )) {
            throw invalid_argument("Invalid IPv4 octet.");
        }

        int octet = stoi(part);

        if (octet > 255) {
            throw invalid_argument("IPv4 octet out of range.");
        }

        octets.push_back(octet);
    }

    if (octets.size() != 4) {
        throw invalid_argument("IPv4 requires four octets.");
    }

    return to_string(octets[0]) + "." +
           to_string(octets[1]) + "." +
           to_string(octets[2]) + "." +
           to_string(octets[3]);
}

string normalizeHash(const string& value) {

    if (value.size() != 64) {
        throw invalid_argument("SHA-256 must contain 64 hexadecimal characters.");
    }

    string result = value;

    for (char& c : result) {

        if (!isxdigit(static_cast<unsigned char>(c))) {
            throw invalid_argument("Invalid SHA-256 hash.");
        }

        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }

    return result;
}

struct ThreatActor {
    string id;
    string name;
    string motivation;
    vector<string> aliases;
};

struct Campaign {
    string id;
    string name;
    string actorId;
    vector<string> objectives;
    vector<string> sectors;
};

struct Indicator {

    string id;
    string value;
    IndicatorType type;

    string source;
    string description;

    int confidence;
    Severity severity;
    TLP tlp;

    IntelligenceType intelligenceType;

    chrono::system_clock::time_point firstSeen;
    chrono::system_clock::time_point lastSeen;
    chrono::system_clock::time_point expiresAt;

    string actorId;
    string campaignId;

    set<string> tags;
    set<string> references;

    IndicatorStatus status = IndicatorStatus::Active;

    double riskScore(
        chrono::system_clock::time_point now
    ) const {

        if (
            status != IndicatorStatus::Active ||
            now >= expiresAt
        ) {
            return 0.0;
        }

        const double ageHours =
            chrono::duration<double>(
                now - lastSeen
            ).count() / 3600.0;

        const double recency = max(
            0.0,
            100.0 - max(0.0, ageHours) / 24.0 * 5.0
        );

        return min(
            100.0,
            confidence * 0.4 +
            static_cast<int>(severity) * 25.0 * 0.4 +
            recency * 0.2
        );
    }
};

class SharingPolicy {

public:

    static bool canShare(
        TLP classification,
        const string& recipient
    ) {

        static const set<string> validGroups = {
            "public",
            "community",
            "organization",
            "designated_group",
            "internal"
        };

        if (!validGroups.count(recipient)) {
            return false;
        }

        switch (classification) {

            case TLP::Clear:
                return true;

            case TLP::Green:
                return recipient != "public";

            case TLP::Amber:
                return recipient == "organization" ||
                       recipient == "designated_group" ||
                       recipient == "internal";

            case TLP::AmberStrict:
                return recipient == "designated_group" ||
                       recipient == "internal";

            case TLP::Red:
                return false;
        }

        return false;
    }
};

class ThreatIntelligenceEngine {

private:

    unordered_map<string, ThreatActor> actors;
    unordered_map<string, Campaign> campaigns;
    unordered_map<string, Indicator> indicators;

    string createIndicatorId(
        IndicatorType type,
        const string& value
    ) const {

        // Deterministic identifier for in-process deduplication.
        hash<string> hasher;

        return to_string(
            hasher(to_string(static_cast<int>(type)) + ":" + value)
        );
    }

    string normalize(
        IndicatorType type,
        const string& value
    ) const {

        if (value.empty() || value.size() > 2048) {
            throw invalid_argument("Invalid indicator length.");
        }

        switch (type) {
            case IndicatorType::IPv4:
                return normalizeIPv4(value);

            case IndicatorType::Domain:
                return normalizeDomain(value);

            case IndicatorType::SHA256:
                return normalizeHash(value);
        }

        throw invalid_argument("Unsupported indicator type.");
    }

public:

    void registerActor(const ThreatActor& actor) {

        if (actor.id.empty() || actor.name.empty()) {
            throw invalid_argument("Invalid actor.");
        }

        if (actors.count(actor.id)) {
            throw runtime_error("Duplicate actor.");
        }

        actors.emplace(actor.id, actor);
    }

    void registerCampaign(const Campaign& campaign) {

        if (!actors.count(campaign.actorId)) {
            throw runtime_error("Unknown campaign actor.");
        }

        if (campaigns.count(campaign.id)) {
            throw runtime_error("Duplicate campaign.");
        }

        campaigns.emplace(campaign.id, campaign);
    }

    string ingest(Indicator indicator) {

        indicator.value = normalize(
            indicator.type,
            indicator.value
        );

        if (
            indicator.confidence < 0 ||
            indicator.confidence > 100
        ) {
            throw invalid_argument("Invalid confidence.");
        }

        if (indicator.source.empty()) {
            throw invalid_argument("Source is required.");
        }

        if (indicator.lastSeen < indicator.firstSeen) {
            throw invalid_argument("Invalid observation timestamps.");
        }

        if (indicator.expiresAt <= indicator.firstSeen) {
            throw invalid_argument("Invalid expiration timestamp.");
        }

        if (
            !indicator.actorId.empty() &&
            !actors.count(indicator.actorId)
        ) {
            throw runtime_error("Unknown threat actor.");
        }

        if (
            !indicator.campaignId.empty() &&
            !campaigns.count(indicator.campaignId)
        ) {
            throw runtime_error("Unknown campaign.");
        }

        indicator.id = createIndicatorId(
            indicator.type,
            indicator.value
        );

        auto existing = indicators.find(indicator.id);

        if (existing != indicators.end()) {

            Indicator& current = existing->second;

            current.confidence = max(
                current.confidence,
                indicator.confidence
            );

            if (
                static_cast<int>(indicator.severity) >
                static_cast<int>(current.severity)
            ) {
                current.severity = indicator.severity;
            }

            current.lastSeen = max(
                current.lastSeen,
                indicator.lastSeen
            );

            current.expiresAt = max(
                current.expiresAt,
                indicator.expiresAt
            );

            current.tags.insert(
                indicator.tags.begin(),
                indicator.tags.end()
            );

            current.references.insert(indicator.source);

            return current.id;
        }

        indicator.references.insert(indicator.source);

        indicators.emplace(
            indicator.id,
            std::move(indicator)
        );

        return createIndicatorId(
            indicators.rbegin()->second.type,
            indicators.rbegin()->second.value
        );
    }

    vector<const Indicator*> search(
        optional<IndicatorType> type = nullopt,
        optional<IntelligenceType> intelligence = nullopt,
        optional<string> tag = nullopt
    ) const {

        vector<const Indicator*> results;

        auto now = chrono::system_clock::now();

        for (const auto& entry : indicators) {

            const Indicator& item = entry.second;

            if (
                item.status != IndicatorStatus::Active ||
                item.expiresAt <= now
            ) {
                continue;
            }

            if (type && item.type != *type) continue;

            if (
                intelligence &&
                item.intelligenceType != *intelligence
            ) continue;

            if (tag && !item.tags.count(*tag)) continue;

            results.push_back(&item);
        }

        sort(
            results.begin(),
            results.end(),
            [now](const Indicator* a, const Indicator* b) {
                return a->riskScore(now) > b->riskScore(now);
            }
        );

        return results;
    }

    vector<const Indicator*> correlate(
        const string& campaignId
    ) const {

        if (!campaigns.count(campaignId)) {
            throw runtime_error("Campaign not found.");
        }

        vector<const Indicator*> results;

        for (const auto& entry : indicators) {

            if (
                entry.second.campaignId == campaignId &&
                entry.second.status == IndicatorStatus::Active &&
                entry.second.expiresAt > chrono::system_clock::now()
            ) {
                results.push_back(&entry.second);
            }
        }

        return results;
    }

    void updateStatus(
        const string& id,
        IndicatorStatus status
    ) {

        auto found = indicators.find(id);

        if (found == indicators.end()) {
            throw runtime_error("Indicator not found.");
        }

        found->second.status = status;
    }

    size_t expireIndicators() {

        size_t count = 0;
        auto now = chrono::system_clock::now();

        for (auto& entry : indicators) {

            Indicator& item = entry.second;

            if (
                item.status == IndicatorStatus::Active &&
                item.expiresAt <= now
            ) {
                item.status = IndicatorStatus::Expired;
                count++;
            }
        }

        return count;
    }

    vector<const Indicator*> evaluateObservable(
        IndicatorType type,
        const string& observable
    ) const {

        const string normalized = normalize(type, observable);

        vector<const Indicator*> matches;

        for (const Indicator* item : search(type)) {

            if (item->value == normalized) {
                matches.push_back(item);
            }
        }

        return matches;
    }

    void printReport() const {

        auto active = search();

        map<string, int> intelligenceCounts;
        map<string, int> severityCounts;

        for (const Indicator* item : active) {

            intelligenceCounts[
                toString(item->intelligenceType)
            ]++;

            severityCounts[
                toString(item->severity)
            ]++;
        }

        cout << "\nTHREAT INTELLIGENCE REPORT\n";
        cout << "============================\n";

        cout << "Total actors: " << actors.size() << "\n";
        cout << "Total campaigns: " << campaigns.size() << "\n";
        cout << "Active indicators: " << active.size() << "\n";

        cout << "\nINTELLIGENCE DISTRIBUTION\n";

        for (const auto& entry : intelligenceCounts) {
            cout << entry.first << ": "
                 << entry.second << "\n";
        }

        cout << "\nSEVERITY DISTRIBUTION\n";

        for (const auto& entry : severityCounts) {
            cout << entry.first << ": "
                 << entry.second << "\n";
        }

        cout << "\nPRIORITY INDICATORS\n";

        for (const Indicator* item : active) {

            cout << fixed << setprecision(2)
                 << item->value
                 << " | "
                 << toString(item->severity)
                 << " | Confidence: "
                 << item->confidence
                 << " | Risk: "
                 << item->riskScore(
                     chrono::system_clock::now()
                 )
                 << "\n";
        }
    }
};

int main() {

    try {

        ThreatIntelligenceEngine engine;

        auto now = chrono::system_clock::now();

        engine.registerActor({
            "ACT-001",
            "Example APT",
            "Espionage",
            {"EXAMPLE-APT"}
        });

        engine.registerCampaign({
            "CMP-001",
            "Northern Gateway",
            "ACT-001",
            {"Credential theft", "Data exfiltration"},
            {"Government", "Energy"}
        });

        Indicator ip;

        ip.value = "203.0.113.25";
        ip.type = IndicatorType::IPv4;
        ip.source = "Example-TI-Feed";
        ip.description = "Simulated command-and-control address.";
        ip.confidence = 95;
        ip.severity = Severity::Critical;
        ip.tlp = TLP::Amber;
        ip.intelligenceType = IntelligenceType::Tactical;
        ip.firstSeen = now;
        ip.lastSeen = now;
        ip.expiresAt = now + chrono::hours(24 * 30);
        ip.actorId = "ACT-001";
        ip.campaignId = "CMP-001";
        ip.tags = {"c2", "malware"};

        string ipId = engine.ingest(ip);

        Indicator domain;

        domain.value = "MALICIOUS-EXAMPLE.ORG";
        domain.type = IndicatorType::Domain;
        domain.source = "OSINT-Feed";
        domain.description = "Simulated phishing infrastructure.";
        domain.confidence = 85;
        domain.severity = Severity::High;
        domain.tlp = TLP::Green;
        domain.intelligenceType = IntelligenceType::Operational;
        domain.firstSeen = now;
        domain.lastSeen = now;
        domain.expiresAt = now + chrono::hours(24 * 15);
        domain.actorId = "ACT-001";
        domain.campaignId = "CMP-001";
        domain.tags = {"phishing", "infrastructure"};

        engine.ingest(domain);

        cout << "INGESTION COMPLETED\n";
        cout << "Indicator ID: " << ipId << "\n";

        cout << "\nOBSERVABLE MATCHING\n";

        auto matches = engine.evaluateObservable(
            IndicatorType::IPv4,
            "203.0.113.25"
        );

        for (const Indicator* item : matches) {
            cout << item->value << " matched. "
                 << "Confidence: " << item->confidence
                 << "\n";
        }

        cout << "\nCAMPAIGN CORRELATION\n";

        auto correlated = engine.correlate("CMP-001");

        for (const Indicator* item : correlated) {
            cout << item->value << "\n";
        }

        cout << "\nTLP POLICY\n";

        cout << boolalpha
             << "AMBER to organization: "
             << SharingPolicy::canShare(
                    TLP::Amber,
                    "organization"
                )
             << "\n";

        cout << "RED to public: "
             << SharingPolicy::canShare(
                    TLP::Red,
                    "public"
                )
             << "\n";

        engine.printReport();

        cout << "\nINVALID INDICATOR TEST\n";

        try {
            normalizeIPv4("999.999.999.999");
        } catch (const exception& error) {
            cout << "Rejected: " << error.what() << "\n";
        }

    } catch (const exception& error) {

        cerr << "SYSTEM ERROR: "
             << error.what() << "\n";

        return 1;
    }

    return 0;
}
