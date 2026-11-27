#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
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
#include <utility>
#include <vector>

/*
 * IOC Investigation and Repository-Independent Threat
 * Correlation Engine.
 *
 * C++17 implementation.
 *
 * Domain:
 * - Indicator registration
 * - IOC validation and normalization
 * - Security event correlation
 * - Threat confidence and severity
 * - Allowlist enforcement
 * - Indicator expiration
 * - Investigation cases
 * - Merge-free deterministic threat evaluation
 *
 * IP validation and normalization use standard-library
 * validation rules for textual IPv4 and IPv6 representations.
 * IPv6 canonical compression is intentionally not implemented.
 */

enum class IOCType {
    IP,
    DOMAIN,
    HASH,
    URL,
    FILENAME,
    REGISTRY
};

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class CaseStatus {
    OPEN,
    INVESTIGATING,
    CONTAINED,
    CLOSED
};

enum class EventSource {
    FIREWALL,
    DNS,
    ENDPOINT,
    PROXY,
    FILESYSTEM,
    REGISTRY
};

std::string lower(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        }
    );

    return value;
}

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");

    if (first == std::string::npos) {
        return "";
    }

    const auto last = value.find_last_not_of(" \t\r\n");

    return value.substr(first, last - first + 1);
}

std::string typeName(IOCType type) {
    switch (type) {
        case IOCType::IP: return "IP";
        case IOCType::DOMAIN: return "DOMAIN";
        case IOCType::HASH: return "HASH";
        case IOCType::URL: return "URL";
        case IOCType::FILENAME: return "FILENAME";
        case IOCType::REGISTRY: return "REGISTRY";
    }

    throw std::logic_error("Unknown IOC type");
}

std::string severityName(Severity severity) {
    switch (severity) {
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }

    throw std::logic_error("Unknown severity");
}

std::string caseStatusName(CaseStatus status) {
    switch (status) {
        case CaseStatus::OPEN: return "OPEN";
        case CaseStatus::INVESTIGATING: return "INVESTIGATING";
        case CaseStatus::CONTAINED: return "CONTAINED";
        case CaseStatus::CLOSED: return "CLOSED";
    }

    throw std::logic_error("Unknown case status");
}

bool validIPv4(const std::string& value) {
    std::stringstream stream(value);
    std::string segment;
    int count = 0;

    while (std::getline(stream, segment, '.')) {
        if (segment.empty() || segment.size() > 3) {
            return false;
        }

        if (segment.size() > 1 && segment[0] == '0') {
            return false;
        }

        if (!std::all_of(
                segment.begin(), segment.end(),
                [](unsigned char c) {
                    return std::isdigit(c);
                })) {
            return false;
        }

        int number = std::stoi(segment);

        if (number > 255) {
            return false;
        }

        ++count;
    }

    return count == 4;
}

bool validIPv6(const std::string& value) {
    if (value.find(':') == std::string::npos ||
        value.size() > 45) {
        return false;
    }

    int doubleColon = value.find("::") != std::string::npos ? 1 : 0;

    if (value.find("::") != std::string::npos &&
        value.find("::", value.find("::") + 2) != std::string::npos) {
        return false;
    }

    std::vector<std::string> groups;
    std::stringstream stream(value);
    std::string group;

    while (std::getline(stream, group, ':')) {
        if (group.empty()) {
            continue;
        }

        if (group.size() > 4 ||
            !std::all_of(
                group.begin(), group.end(),
                [](unsigned char c) {
                    return std::isxdigit(c);
                })) {
            return false;
        }

        groups.push_back(group);
    }

    return doubleColon
        ? groups.size() < 8
        : groups.size() == 8;
}

bool validIP(const std::string& value) {
    return validIPv4(value) || validIPv6(value);
}

std::string normalizeDomain(std::string value) {
    value = lower(trim(value));

    if (!value.empty() && value.back() == '.') {
        value.pop_back();
    }

    if (value.empty() || value.size() > 253) {
        throw std::invalid_argument("Invalid domain length");
    }

    std::stringstream stream(value);
    std::string label;
    int labels = 0;

    while (std::getline(stream, label, '.')) {
        if (label.empty() || label.size() > 63) {
            throw std::invalid_argument("Invalid domain label");
        }

        if (!std::isalnum(static_cast<unsigned char>(label.front())) ||
            !std::isalnum(static_cast<unsigned char>(label.back()))) {
            throw std::invalid_argument("Invalid domain boundaries");
        }

        for (unsigned char c : label) {
            if (!std::isalnum(c) && c != '-') {
                throw std::invalid_argument("Invalid domain character");
            }
        }

        ++labels;
    }

    if (labels < 2) {
        throw std::invalid_argument("Fully qualified domain required");
    }

    return value;
}

std::string normalizeHash(std::string value) {
    value = lower(trim(value));

    if (value.size() != 32 &&
        value.size() != 40 &&
        value.size() != 64) {
        throw std::invalid_argument("Unsupported hash length");
    }

    for (unsigned char c : value) {
        if (!std::isxdigit(c)) {
            throw std::invalid_argument("Invalid hash character");
        }
    }

    return value;
}

std::string normalizeFilename(std::string value) {
    value = lower(trim(value));

    if (value.empty() || value.size() > 255) {
        throw std::invalid_argument("Invalid filename length");
    }

    for (unsigned char c : value) {
        if (c == '/' || c == '\\' || c == '\0' ||
            c == '\r' || c == '\n') {
            throw std::invalid_argument("Invalid filename");
        }
    }

    return value;
}

std::string normalizeRegistry(std::string value) {
    value = trim(value);

    const std::vector<std::pair<std::string, std::string>> aliases = {
        {"HKEY_LOCAL_MACHINE", "HKLM"},
        {"HKEY_CURRENT_USER", "HKCU"},
        {"HKEY_CLASSES_ROOT", "HKCR"},
        {"HKEY_USERS", "HKU"}
    };

    for (const auto& [longName, shortName] : aliases) {
        if (value.size() >= longName.size() &&
            lower(value.substr(0, longName.size())) == lower(longName)) {
            value.replace(0, longName.size(), shortName);
            break;
        }
    }

    if (!(value.rfind("HKLM\\", 0) == 0 ||
          value.rfind("HKCU\\", 0) == 0 ||
          value.rfind("HKCR\\", 0) == 0 ||
          value.rfind("HKU\\", 0) == 0)) {
        throw std::invalid_argument("Unsupported registry root");
    }

    if (value.find('\0') != std::string::npos) {
        throw std::invalid_argument("Invalid registry character");
    }

    return lower(value);
}

std::string normalizeIOC(IOCType type, std::string value) {
    value = trim(value);

    switch (type) {
        case IOCType::IP:
            if (!validIP(value)) {
                throw std::invalid_argument("Invalid IP address");
            }
            return lower(value);

        case IOCType::DOMAIN:
            return normalizeDomain(value);

        case IOCType::HASH:
            return normalizeHash(value);

        case IOCType::URL: {
            if (value.size() > 4096) {
                throw std::invalid_argument("URL too long");
            }

            std::regex pattern(
                R"(^(https?)://([^/?#:@]+)(:[0-9]{1,5})?([^?#]*)(\?[^#]*)?(#.*)?$)",
                std::regex::icase
            );

            std::smatch match;

            if (!std::regex_match(value, match, pattern)) {
                throw std::invalid_argument("Invalid HTTP URL");
            }

            std::string host = lower(match[2].str());
            std::string port = match[3].str();

            if (port.size() > 1 &&
                std::stoi(port.substr(1)) > 65535) {
                throw std::invalid_argument("Invalid URL port");
            }

            if (host.find('.') != std::string::npos &&
                !validIPv4(host)) {
                host = normalizeDomain(host);
            }

            return lower(match[1].str()) + "://" + host +
                port + match[4].str() + match[5].str();
        }

        case IOCType::FILENAME:
            return normalizeFilename(value);

        case IOCType::REGISTRY:
            return normalizeRegistry(value);
    }

    throw std::invalid_argument("Unknown IOC type");
}

struct IOC {
    std::string id;
    IOCType type;
    std::string value;
    std::string source;
    int confidence;
    Severity severity;
    std::set<std::string> tags;
    bool active = true;
    std::optional<std::chrono::system_clock::time_point> expiresAt;

    IOC(
        IOCType type_,
        std::string value_,
        std::string source_,
        int confidence_,
        Severity severity_
    ) :
        type(type_),
        value(normalizeIOC(type_, value_)),
        source(trim(source_)),
        confidence(confidence_),
        severity(severity_) {

        if (source.empty()) {
            throw std::invalid_argument("IOC source required");
        }

        if (confidence < 0 || confidence > 100) {
            throw std::invalid_argument("Confidence must be 0-100");
        }

        id = typeName(type) + ":" + value;
    }

    bool isActive() const {
        return active &&
            (!expiresAt ||
             *expiresAt > std::chrono::system_clock::now());
    }
};

struct SecurityEvent {
    std::string id;
    EventSource source;
    IOCType type;
    std::string value;
    std::string asset;
    std::chrono::system_clock::time_point timestamp;
};

struct Match {
    std::string eventId;
    std::string iocId;
    std::string value;
    std::string asset;
    int confidence;
    Severity severity;
};

class IOCRepository {
private:
    std::unordered_map<std::string, IOC> indicators;
    std::set<std::string> allowlist;

    static std::string makeKey(IOCType type, const std::string& value) {
        return typeName(type) + ":" + value;
    }

public:
    void add(const IOC& indicator) {
        const std::string key = makeKey(
            indicator.type, indicator.value
        );

        if (indicators.find(key) != indicators.end()) {
            throw std::invalid_argument("Duplicate IOC");
        }

        indicators.emplace(key, indicator);
    }

    const IOC* find(IOCType type, const std::string& value) const {
        const std::string normalized = normalizeIOC(type, value);
        const std::string key = makeKey(type, normalized);

        auto it = indicators.find(key);

        return it == indicators.end() ? nullptr : &it->second;
    }

    void allow(IOCType type, const std::string& value) {
        allowlist.insert(
            makeKey(type, normalizeIOC(type, value))
        );
    }

    bool isAllowed(IOCType type, const std::string& value) const {
        return allowlist.count(makeKey(type, value)) > 0;
    }

    std::size_t size() const {
        return indicators.size();
    }

    std::size_t activeCount() const {
        return std::count_if(
            indicators.begin(),
            indicators.end(),
            [](const auto& item) {
                return item.second.isActive();
            }
        );
    }
};

class ThreatEngine {
private:
    const IOCRepository& repository;
    std::vector<std::string> audit;

public:
    explicit ThreatEngine(const IOCRepository& repository_)
        : repository(repository_) {}

    std::optional<Match> investigate(
        const SecurityEvent& event
    ) {
        const std::string normalized = normalizeIOC(
            event.type, event.value
        );

        const IOC* indicator = repository.find(
            event.type, normalized
        );

        if (!indicator || !indicator->isActive()) {
            return std::nullopt;
        }

        if (repository.isAllowed(event.type, normalized)) {
            audit.push_back("ALLOWLISTED:" + event.id);
            return std::nullopt;
        }

        audit.push_back("MATCH:" + event.id);

        return Match{
            event.id,
            indicator->id,
            indicator->value,
            event.asset,
            indicator->confidence,
            indicator->severity
        };
    }

    std::vector<Match> investigateBatch(
        const std::vector<SecurityEvent>& events
    ) {
        std::vector<Match> matches;

        for (const auto& event : events) {
            auto result = investigate(event);

            if (result) {
                matches.push_back(*result);
            }
        }

        return matches;
    }

    const std::vector<std::string>& getAudit() const {
        return audit;
    }
};

class ThreatPolicy {
public:
    static int priority(const std::vector<Match>& matches) {
        int maximum = 0;

        for (const auto& match : matches) {
            int weight = 1;

            switch (match.severity) {
                case Severity::LOW: weight = 1; break;
                case Severity::MEDIUM: weight = 2; break;
                case Severity::HIGH: weight = 3; break;
                case Severity::CRITICAL: weight = 4; break;
            }

            maximum = std::max(
                maximum,
                match.confidence * weight / 4
            );
        }

        return std::min(100, maximum);
    }
};

class InvestigationCase {
private:
    std::string id;
    std::string title;
    CaseStatus status;
    std::vector<Match> matches;

public:
    InvestigationCase(std::string id_, std::string title_)
        : id(std::move(id_)),
          title(std::move(title_)),
          status(CaseStatus::OPEN) {

        if (id.empty() || title.empty()) {
            throw std::invalid_argument(
                "Case ID and title required"
            );
        }
    }

    void addMatch(const Match& match) {
        if (status == CaseStatus::CLOSED) {
            throw std::logic_error("Case is closed");
        }

        auto duplicate = std::find_if(
            matches.begin(), matches.end(),
            [&](const Match& existing) {
                return existing.eventId == match.eventId &&
                       existing.iocId == match.iocId;
            }
        );

        if (duplicate == matches.end()) {
            matches.push_back(match);
        }
    }

    void transition(CaseStatus next) {
        bool valid = false;

        switch (status) {
            case CaseStatus::OPEN:
                valid = next == CaseStatus::INVESTIGATING ||
                        next == CaseStatus::CLOSED;
                break;

            case CaseStatus::INVESTIGATING:
                valid = next == CaseStatus::CONTAINED ||
                        next == CaseStatus::CLOSED;
                break;

            case CaseStatus::CONTAINED:
                valid = next == CaseStatus::INVESTIGATING ||
                        next == CaseStatus::CLOSED;
                break;

            case CaseStatus::CLOSED:
                valid = false;
                break;
        }

        if (!valid) {
            throw std::logic_error("Invalid case transition");
        }

        status = next;
    }

    CaseStatus getStatus() const {
        return status;
    }

    const std::vector<Match>& getMatches() const {
        return matches;
    }

    const std::string& getId() const {
        return id;
    }
};

void runTests() {
    if (!validIPv4("203.0.113.45")) {
        throw std::runtime_error("IPv4 validation failed");
    }

    if (validIPv4("999.999.999.999")) {
        throw std::runtime_error("Invalid IPv4 accepted");
    }

    if (normalizeHash(std::string(64, 'A')) !=
        std::string(64, 'a')) {
        throw std::runtime_error("Hash normalization failed");
    }

    bool invalidHashRejected = false;

    try {
        normalizeHash("12345");
    } catch (const std::invalid_argument&) {
        invalidHashRejected = true;
    }

    if (!invalidHashRejected) {
        throw std::runtime_error("Invalid hash accepted");
    }

    if (normalizeDomain("MALWARE.EXAMPLE.") !=
        "malware.example") {
        throw std::runtime_error("Domain normalization failed");
    }

    IOCRepository repository;

    repository.add(IOC(
        IOCType::IP,
        "203.0.113.45",
        "Test Feed",
        95,
        Severity::CRITICAL
    ));

    bool duplicateRejected = false;

    try {
        repository.add(IOC(
            IOCType::IP,
            "203.0.113.45",
            "Second Feed",
            80,
            Severity::HIGH
        ));
    } catch (const std::invalid_argument&) {
        duplicateRejected = true;
    }

    if (!duplicateRejected) {
        throw std::runtime_error("Duplicate IOC accepted");
    }

    std::cout << "C++17 validation tests passed.\n";
}

int main() {
    try {
        IOCRepository repository;

        IOC ip(
            IOCType::IP,
            "203.0.113.45",
            "Firewall Threat Feed",
            95,
            Severity::CRITICAL
        );

        IOC domain(
            IOCType::DOMAIN,
            "malware.example",
            "DNS Intelligence",
            90,
            Severity::HIGH
        );

        IOC hash(
            IOCType::HASH,
            std::string(64, 'a'),
            "Endpoint Threat Feed",
            99,
            Severity::CRITICAL
        );

        IOC url(
            IOCType::URL,
            "https://malware.example/payload",
            "URL Threat Feed",
            92,
            Severity::HIGH
        );

        IOC filename(
            IOCType::FILENAME,
            "suspicious.exe",
            "Endpoint Investigation",
            80,
            Severity::MEDIUM
        );

        IOC registry(
            IOCType::REGISTRY,
            "HKEY_LOCAL_MACHINE\\Software\\BadActor\\Persistence",
            "Registry Intelligence",
            90,
            Severity::HIGH
        );

        repository.add(ip);
        repository.add(domain);
        repository.add(hash);
        repository.add(url);
        repository.add(filename);
        repository.add(registry);

        repository.allow(IOCType::IP, "192.0.2.10");

        const auto now = std::chrono::system_clock::now();

        std::vector<SecurityEvent> events = {
            {"EVT-001", EventSource::FIREWALL,
             IOCType::IP, "203.0.113.45", "HOST-01", now},

            {"EVT-002", EventSource::DNS,
             IOCType::DOMAIN, "MALWARE.EXAMPLE.",
             "HOST-02", now},

            {"EVT-003", EventSource::ENDPOINT,
             IOCType::HASH, std::string(64, 'a'),
             "SERVER-01", now},

            {"EVT-004", EventSource::PROXY,
             IOCType::URL, "https://malware.example/payload",
             "HOST-03", now},

            {"EVT-005", EventSource::FILESYSTEM,
             IOCType::FILENAME, "suspicious.exe",
             "HOST-04", now},

            {"EVT-006", EventSource::REGISTRY,
             IOCType::REGISTRY,
             "HKLM\\Software\\BadActor\\Persistence",
             "HOST-05", now}
        };

        ThreatEngine engine(repository);

        auto matches = engine.investigateBatch(events);

        InvestigationCase investigation(
            "CASE-2026-001",
            "Suspicious endpoint and network activity"
        );

        for (const auto& match : matches) {
            investigation.addMatch(match);
        }

        if (!matches.empty()) {
            investigation.transition(CaseStatus::INVESTIGATING);
        }

        std::cout << "\nIOC INVESTIGATION REPORT\n";
        std::cout << "========================\n";

        std::cout << "Registered indicators: "
                  << repository.size() << "\n";

        std::cout << "Active indicators: "
                  << repository.activeCount() << "\n";

        std::cout << "Events analyzed: "
                  << events.size() << "\n";

        std::cout << "Confirmed matches: "
                  << matches.size() << "\n";

        std::cout << "Threat priority: "
                  << ThreatPolicy::priority(matches)
                  << "/100\n";

        for (const auto& match : matches) {
            std::cout
                << "\nEvent: " << match.eventId
                << "\nAsset: " << match.asset
                << "\nIOC: " << match.value
                << "\nConfidence: " << match.confidence
                << "%"
                << "\nSeverity: " << severityName(match.severity)
                << "\n";
        }

        std::cout << "\nInvestigation: "
                  << investigation.getId() << "\n";

        std::cout << "Case status: "
                  << caseStatusName(investigation.getStatus())
                  << "\n";

        std::cout << "Audit entries: "
                  << engine.getAudit().size() << "\n";

        runTests();

    } catch (const std::exception& error) {
        std::cerr << "Execution failed: "
                  << error.what() << "\n";

        return 1;
    }

    return 0;
}
