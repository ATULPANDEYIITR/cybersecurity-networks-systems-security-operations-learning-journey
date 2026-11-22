/*
 * Security Log Governance and Threat Detection Engine
 *
 * C++17
 *
 * Supports:
 * - Windows and Linux authentication telemetry
 * - Firewall and network connection logs
 * - DNS and proxy telemetry
 * - Application security events
 * - Event validation and deduplication
 * - Brute-force detection
 * - Port scanning detection
 * - DNS anomaly detection
 * - Privilege-change monitoring
 * - Risk-based alert classification
 *
 * Build:
 * g++ -std=c++17 -O2 -Wall -Wextra -pedantic security_logs.cpp -o security_logs
 *
 * Run:
 * ./security_logs
 */

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;


enum class LogSource {
    WINDOWS,
    LINUX,
    FIREWALL,
    DNS,
    PROXY,
    AUTHENTICATION,
    APPLICATION
};

enum class EventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    PRIVILEGE_CHANGE,
    PROCESS_EXECUTION,
    NETWORK_CONNECTION,
    FIREWALL_BLOCK,
    FIREWALL_ALLOW,
    DNS_QUERY,
    HTTP_REQUEST,
    APPLICATION_ERROR,
    FILE_ACCESS
};

enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};


string toString(LogSource source) {
    switch (source) {
        case LogSource::WINDOWS: return "WINDOWS";
        case LogSource::LINUX: return "LINUX";
        case LogSource::FIREWALL: return "FIREWALL";
        case LogSource::DNS: return "DNS";
        case LogSource::PROXY: return "PROXY";
        case LogSource::AUTHENTICATION: return "AUTHENTICATION";
        case LogSource::APPLICATION: return "APPLICATION";
    }

    throw invalid_argument("Unknown source");
}


string toString(EventType type) {
    switch (type) {
        case EventType::LOGIN_SUCCESS: return "LOGIN_SUCCESS";
        case EventType::LOGIN_FAILURE: return "LOGIN_FAILURE";
        case EventType::PRIVILEGE_CHANGE: return "PRIVILEGE_CHANGE";
        case EventType::PROCESS_EXECUTION: return "PROCESS_EXECUTION";
        case EventType::NETWORK_CONNECTION: return "NETWORK_CONNECTION";
        case EventType::FIREWALL_BLOCK: return "FIREWALL_BLOCK";
        case EventType::FIREWALL_ALLOW: return "FIREWALL_ALLOW";
        case EventType::DNS_QUERY: return "DNS_QUERY";
        case EventType::HTTP_REQUEST: return "HTTP_REQUEST";
        case EventType::APPLICATION_ERROR: return "APPLICATION_ERROR";
        case EventType::FILE_ACCESS: return "FILE_ACCESS";
    }

    throw invalid_argument("Unknown event type");
}


string toString(Severity severity) {
    switch (severity) {
        case Severity::INFO: return "INFO";
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }

    throw invalid_argument("Unknown severity");
}


int severityWeight(Severity severity) {
    switch (severity) {
        case Severity::INFO: return 0;
        case Severity::LOW: return 10;
        case Severity::MEDIUM: return 25;
        case Severity::HIGH: return 45;
        case Severity::CRITICAL: return 70;
    }

    return 0;
}


struct SecurityEvent {
    string id;
    long long timestamp;
    LogSource source;
    EventType type;

    string sourceIP;
    string destinationIP;
    string username;
    string hostname;
    string resource;
    string protocol;

    int destinationPort = 0;

    map<string, string> attributes;
};


struct DetectionPolicy {
    size_t failedLoginThreshold = 5;
    size_t portScanThreshold = 10;
    long long windowSeconds = 300;
    size_t dnsLabelThreshold = 50;

    void validate() const {
        if (
            failedLoginThreshold == 0 ||
            portScanThreshold == 0 ||
            windowSeconds <= 0 ||
            dnsLabelThreshold == 0
        ) {
            throw invalid_argument(
                "Detection policy values must be positive."
            );
        }
    }
};


struct SecurityFinding {
    string ruleId;
    string title;
    string entity;
    string description;
    Severity severity;
    double confidence;
    vector<string> eventIds;
    map<string, string> evidence;

    int riskScore() const {
        return min(
            100,
            static_cast<int>(
                round(severityWeight(severity) * confidence)
            )
        );
    }
};


bool validIPv4(const string& ip) {
    stringstream stream(ip);
    string part;
    int count = 0;

    while (getline(stream, part, '.')) {
        if (part.empty() || part.size() > 3) return false;

        if (!all_of(part.begin(), part.end(), ::isdigit)) {
            return false;
        }

        if (part.size() > 1 && part[0] == '0') {
            return false;
        }

        int value = stoi(part);

        if (value > 255) return false;

        count++;
    }

    return count == 4;
}


void validateEvent(const SecurityEvent& event) {
    if (event.id.empty() || event.id.size() > 128) {
        throw invalid_argument("Invalid event identifier.");
    }

    if (event.timestamp <= 0) {
        throw invalid_argument("Invalid event timestamp.");
    }

    if (!event.sourceIP.empty() &&
        !validIPv4(event.sourceIP)) {
        throw invalid_argument("Invalid source IPv4 address.");
    }

    if (!event.destinationIP.empty() &&
        !validIPv4(event.destinationIP)) {
        throw invalid_argument("Invalid destination IPv4 address.");
    }

    if (
        event.destinationPort < 0 ||
        event.destinationPort > 65535
    ) {
        throw invalid_argument("Invalid destination port.");
    }

    if (event.resource.size() > 8192) {
        throw invalid_argument("Resource exceeds maximum length.");
    }
}


class EventRepository {
private:
    vector<SecurityEvent> events;
    unordered_set<string> eventIds;

public:
    void insert(const SecurityEvent& event) {
        validateEvent(event);

        if (eventIds.count(event.id)) {
            throw invalid_argument("Duplicate event identifier.");
        }

        events.push_back(event);
        eventIds.insert(event.id);
    }

    const vector<SecurityEvent>& getAll() const {
        return events;
    }

    size_t size() const {
        return events.size();
    }
};


class SecurityDetectionEngine {
private:
    DetectionPolicy policy;

    static double entropy(const string& value) {
        if (value.empty()) return 0.0;

        unordered_map<char, size_t> counts;

        for (char character : value) {
            counts[character]++;
        }

        double result = 0.0;

        for (const auto& item : counts) {
            double probability =
                static_cast<double>(item.second) / value.size();

            result -= probability * log2(probability);
        }

        return result;
    }

    vector<SecurityFinding> detectBruteForce(
        const vector<SecurityEvent>& events
    ) const {
        map<pair<string, string>, vector<SecurityEvent>> groups;

        for (const auto& event : events) {
            if (
                event.type == EventType::LOGIN_FAILURE &&
                !event.sourceIP.empty()
            ) {
                groups[
                    {event.sourceIP, event.username}
                ].push_back(event);
            }
        }

        vector<SecurityFinding> findings;

        for (auto& group : groups) {
            auto& records = group.second;

            sort(
                records.begin(),
                records.end(),
                [](const auto& a, const auto& b) {
                    return a.timestamp < b.timestamp;
                }
            );

            size_t start = 0;

            for (size_t end = 0; end < records.size(); end++) {
                while (
                    records[end].timestamp -
                    records[start].timestamp >
                    policy.windowSeconds
                ) {
                    start++;
                }

                size_t count = end - start + 1;

                if (count >= policy.failedLoginThreshold) {
                    SecurityFinding finding;

                    finding.ruleId = "AUTH-001";
                    finding.title =
                        "Repeated authentication failures";
                    finding.entity = group.first.first;
                    finding.description =
                        "Multiple failed authentication attempts "
                        "from the same source.";
                    finding.severity = Severity::HIGH;
                    finding.confidence = 0.95;

                    finding.evidence["username"] =
                        group.first.second;

                    finding.evidence["attempts"] =
                        to_string(count);

                    for (
                        size_t index = start;
                        index <= end;
                        index++
                    ) {
                        finding.eventIds.push_back(
                            records[index].id
                        );
                    }

                    findings.push_back(move(finding));
                    break;
                }
            }
        }

        return findings;
    }

    vector<SecurityFinding> detectPortScan(
        const vector<SecurityEvent>& events
    ) const {
        map<string, vector<SecurityEvent>> groups;

        for (const auto& event : events) {
            if (
                event.type == EventType::NETWORK_CONNECTION &&
                !event.sourceIP.empty() &&
                event.destinationPort > 0
            ) {
                groups[event.sourceIP].push_back(event);
            }
        }

        vector<SecurityFinding> findings;

        for (auto& group : groups) {
            auto& records = group.second;

            sort(
                records.begin(),
                records.end(),
                [](const auto& a, const auto& b) {
                    return a.timestamp < b.timestamp;
                }
            );

            size_t start = 0;

            for (size_t end = 0; end < records.size(); end++) {
                while (
                    records[end].timestamp -
                    records[start].timestamp >
                    policy.windowSeconds
                ) {
                    start++;
                }

                set<int> ports;
                vector<string> ids;

                for (size_t index = start; index <= end; index++) {
                    ports.insert(
                        records[index].destinationPort
                    );

                    ids.push_back(records[index].id);
                }

                if (ports.size() >= policy.portScanThreshold) {
                    SecurityFinding finding;

                    finding.ruleId = "NET-001";
                    finding.title = "Potential port scan";
                    finding.entity = group.first;
                    finding.description =
                        "A source contacted multiple destination ports.";
                    finding.severity = Severity::HIGH;
                    finding.confidence = 0.90;
                    finding.eventIds = move(ids);

                    finding.evidence["unique_ports"] =
                        to_string(ports.size());

                    findings.push_back(move(finding));
                    break;
                }
            }
        }

        return findings;
    }

    vector<SecurityFinding> detectDns(
        const vector<SecurityEvent>& events
    ) const {
        vector<SecurityFinding> findings;

        for (const auto& event : events) {
            if (event.type != EventType::DNS_QUERY) {
                continue;
            }

            auto iterator = event.attributes.find("query");

            if (iterator == event.attributes.end()) {
                continue;
            }

            string domain = iterator->second;

            size_t start = 0;
            size_t longest = 0;

            while (start < domain.size()) {
                size_t end = domain.find('.', start);

                if (end == string::npos) {
                    end = domain.size();
                }

                longest = max(longest, end - start);

                start = end + 1;
            }

            double score = entropy(domain);

            if (
                longest >= policy.dnsLabelThreshold ||
                (domain.size() >= 25 && score >= 3.5)
            ) {
                SecurityFinding finding;

                finding.ruleId = "DNS-001";
                finding.title = "Suspicious DNS query";
                finding.entity = event.sourceIP;
                finding.description =
                    "Unusually long or high-entropy DNS label.";
                finding.severity = Severity::MEDIUM;
                finding.confidence = 0.85;
                finding.eventIds = {event.id};

                finding.evidence["domain"] = domain;
                finding.evidence["entropy"] = to_string(score);

                findings.push_back(move(finding));
            }
        }

        return findings;
    }

    vector<SecurityFinding> detectPrivilegeChanges(
        const vector<SecurityEvent>& events
    ) const {
        vector<SecurityFinding> findings;

        for (const auto& event : events) {
            if (event.type != EventType::PRIVILEGE_CHANGE) {
                continue;
            }

            SecurityFinding finding;

            finding.ruleId = "AUTH-002";
            finding.title = "Privilege change detected";
            finding.entity = event.username;
            finding.description =
                "An account received elevated privileges.";
            finding.severity = Severity::MEDIUM;
            finding.confidence = 0.85;
            finding.eventIds = {event.id};

            finding.evidence["hostname"] = event.hostname;

            findings.push_back(move(finding));
        }

        return findings;
    }

public:
    explicit SecurityDetectionEngine(DetectionPolicy config)
        : policy(config) {
        policy.validate();
    }

    vector<SecurityFinding> evaluate(
        const vector<SecurityEvent>& events
    ) const {
        vector<SecurityFinding> findings;

        auto append = [&](vector<SecurityFinding> result) {
            findings.insert(
                findings.end(),
                make_move_iterator(result.begin()),
                make_move_iterator(result.end())
            );
        };

        append(detectBruteForce(events));
        append(detectPortScan(events));
        append(detectDns(events));
        append(detectPrivilegeChanges(events));

        sort(
            findings.begin(),
            findings.end(),
            [](const auto& a, const auto& b) {
                return a.riskScore() > b.riskScore();
            }
        );

        return findings;
    }
};


class SecurityReporter {
public:
    static void print(
        const vector<SecurityEvent>& events,
        const vector<SecurityFinding>& findings
    ) {
        map<string, size_t> sourceCounts;
        map<string, size_t> severityCounts;

        for (const auto& event : events) {
            sourceCounts[toString(event.source)]++;
        }

        for (const auto& finding : findings) {
            severityCounts[toString(finding.severity)]++;
        }

        cout << "\n========== SECURITY LOG REPORT ==========\n";

        cout << "Total events: " << events.size() << "\n";
        cout << "Total findings: " << findings.size() << "\n";

        cout << "\nSource distribution:\n";

        for (const auto& item : sourceCounts) {
            cout << "  " << item.first
                 << ": " << item.second << "\n";
        }

        cout << "\nFindings:\n";

        for (const auto& finding : findings) {
            cout << "\n[" << finding.ruleId << "] "
                 << finding.title << "\n";

            cout << "Severity: "
                 << toString(finding.severity) << "\n";

            cout << "Entity: "
                 << finding.entity << "\n";

            cout << "Risk score: "
                 << finding.riskScore() << "/100\n";

            cout << "Evidence records: "
                 << finding.eventIds.size() << "\n";

            for (const auto& evidence : finding.evidence) {
                cout << "  " << evidence.first
                     << ": " << evidence.second << "\n";
            }
        }

        cout << "\nSeverity distribution:\n";

        for (const auto& item : severityCounts) {
            cout << "  " << item.first
                 << ": " << item.second << "\n";
        }
    }
};


long long currentTimestamp() {
    // Fixed epoch values keep the demonstration deterministic.
    return 1795344000;
}


vector<SecurityEvent> createSampleEvents() {
    vector<SecurityEvent> events;

    const long long now = currentTimestamp();

    for (int index = 0; index < 7; index++) {
        SecurityEvent event;

        event.id = "auth-" + to_string(index);
        event.timestamp = now - 60 + index * 5;
        event.source = LogSource::AUTHENTICATION;
        event.type = EventType::LOGIN_FAILURE;
        event.sourceIP = "203.0.113.50";
        event.username = "administrator";
        event.hostname = "server-01";

        events.push_back(event);
    }

    for (int index = 0; index < 12; index++) {
        SecurityEvent event;

        event.id = "network-" + to_string(index);
        event.timestamp = now - 40 + index;
        event.source = LogSource::FIREWALL;
        event.type = EventType::NETWORK_CONNECTION;
        event.sourceIP = "198.51.100.20";
        event.destinationIP = "10.0.0.10";
        event.destinationPort = 1000 + index;
        event.protocol = "TCP";

        events.push_back(event);
    }

    SecurityEvent dns;

    dns.id = "dns-001";
    dns.timestamp = now;
    dns.source = LogSource::DNS;
    dns.type = EventType::DNS_QUERY;
    dns.sourceIP = "10.0.0.15";
    dns.attributes["query"] =
        string(65, 'a') + ".example.com";

    events.push_back(dns);

    SecurityEvent privilege;

    privilege.id = "priv-001";
    privilege.timestamp = now;
    privilege.source = LogSource::WINDOWS;
    privilege.type = EventType::PRIVILEGE_CHANGE;
    privilege.username = "administrator";
    privilege.hostname = "server-01";

    events.push_back(privilege);

    return events;
}


void runTests() {
    assert(validIPv4("192.168.1.1"));
    assert(validIPv4("127.0.0.1"));
    assert(!validIPv4("999.999.999.999"));
    assert(!validIPv4("192.168.01.1"));

    DetectionPolicy policy;

    policy.failedLoginThreshold = 3;
    policy.portScanThreshold = 5;

    SecurityDetectionEngine engine(policy);

    auto events = createSampleEvents();

    auto findings = engine.evaluate(events);

    assert(
        any_of(
            findings.begin(),
            findings.end(),
            [](const auto& finding) {
                return finding.ruleId == "AUTH-001";
            }
        )
    );

    assert(
        any_of(
            findings.begin(),
            findings.end(),
            [](const auto& finding) {
                return finding.ruleId == "NET-001";
            }
        )
    );

    assert(
        any_of(
            findings.begin(),
            findings.end(),
            [](const auto& finding) {
                return finding.ruleId == "DNS-001";
            }
        )
    );

    cout << "All C++17 tests passed.\n";
}


int main(int argc, char* argv[]) {
    try {
        if (argc > 1 && string(argv[1]) == "--test") {
            runTests();
            return 0;
        }

        DetectionPolicy policy;

        EventRepository repository;

        for (const auto& event : createSampleEvents()) {
            repository.insert(event);
        }

        SecurityDetectionEngine engine(policy);

        auto findings = engine.evaluate(
            repository.getAll()
        );

        SecurityReporter::print(
            repository.getAll(),
            findings
        );

        return 0;

    } catch (const exception& error) {
        cerr << "Security processing error: "
             << error.what() << "\n";

        return 1;
    }
}
