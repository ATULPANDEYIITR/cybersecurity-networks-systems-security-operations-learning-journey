#include <algorithm>
#include <chrono>
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

/*
 * SIEM FUNDAMENTALS
 *
 * C++17 repository-independent SIEM governance engine.
 *
 * Models:
 * - Security events and structured fields
 * - Equality indexing
 * - Search and time filtering
 * - Correlation rules
 * - Alert generation
 * - Alert state transitions
 * - Merge-independent security monitoring
 *
 * Compile:
 * g++ -std=c++17 -O2 -Wall -Wextra -pedantic siem.cpp -o siem
 */

enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class Category {
    AUTHENTICATION,
    NETWORK,
    ENDPOINT,
    FIREWALL,
    DNS,
    APPLICATION
};

enum class AlertStatus {
    NEW,
    ACKNOWLEDGED,
    INVESTIGATING,
    RESOLVED,
    FALSE_POSITIVE
};

std::string toString(Severity value) {
    switch (value) {
        case Severity::INFO: return "INFO";
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    throw std::invalid_argument("Unknown severity");
}

std::string toString(Category value) {
    switch (value) {
        case Category::AUTHENTICATION: return "authentication";
        case Category::NETWORK: return "network";
        case Category::ENDPOINT: return "endpoint";
        case Category::FIREWALL: return "firewall";
        case Category::DNS: return "dns";
        case Category::APPLICATION: return "application";
    }
    throw std::invalid_argument("Unknown category");
}

std::string toString(AlertStatus value) {
    switch (value) {
        case AlertStatus::NEW: return "NEW";
        case AlertStatus::ACKNOWLEDGED: return "ACKNOWLEDGED";
        case AlertStatus::INVESTIGATING: return "INVESTIGATING";
        case AlertStatus::RESOLVED: return "RESOLVED";
        case AlertStatus::FALSE_POSITIVE: return "FALSE_POSITIVE";
    }
    throw std::invalid_argument("Unknown status");
}

struct SecurityEvent {
    std::string id;
    std::int64_t timestamp;
    std::string source;
    Category category;
    std::string eventType;
    Severity severity;
    std::map<std::string, std::string> fields;

    void validate() const {
        if (id.empty() || id.size() > 128) {
            throw std::invalid_argument("Invalid event ID");
        }

        if (source.empty() || source.size() > 100) {
            throw std::invalid_argument("Invalid event source");
        }

        if (eventType.empty() || eventType.size() > 100) {
            throw std::invalid_argument("Invalid event type");
        }

        for (const auto& field : fields) {
            if (field.first.empty() || field.first.size() > 100) {
                throw std::invalid_argument("Invalid field name");
            }

            if (field.second.size() > 4096) {
                throw std::invalid_argument("Field value too large");
            }
        }
    }

    std::string getField(const std::string& name) const {
        if (name == "event_id") return id;
        if (name == "source") return source;
        if (name == "category") return toString(category);
        if (name == "event_type") return eventType;
        if (name == "severity") return toString(severity);

        auto it = fields.find(name);

        return it == fields.end() ? "" : it->second;
    }
};


struct SearchQuery {
    std::string field;
    std::string value;
    std::int64_t startTime = 0;
    std::int64_t endTime = INT64_MAX;
    std::size_t limit = 1000;
};


struct SearchResult {
    std::vector<SecurityEvent> events;
    std::size_t total = 0;
    double executionMilliseconds = 0.0;
};


struct CorrelationRule {
    std::string id;
    std::string name;
    std::string eventType;
    std::string groupField;
    std::int64_t windowSeconds;
    std::size_t threshold;
    Severity severity;

    void validate() const {
        if (id.empty() || name.empty()) {
            throw std::invalid_argument("Rule identity is required");
        }

        if (windowSeconds <= 0 || threshold == 0) {
            throw std::invalid_argument("Invalid rule threshold or window");
        }
    }
};


struct Alert {
    std::string id;
    std::string ruleId;
    std::string title;
    std::string description;
    Severity severity;
    AlertStatus status;
    std::int64_t createdAt;
    std::vector<std::string> eventIds;
    std::string assignedTo;
};


class SIEMEngine {
private:
    std::unordered_map<std::string, SecurityEvent> events_;

    // field -> value -> event identifiers
    std::unordered_map<
        std::string,
        std::unordered_map<
            std::string,
            std::unordered_set<std::string>
        >
    > indexes_;

    std::unordered_map<std::string, CorrelationRule> rules_;
    std::unordered_map<std::string, Alert> alerts_;

    std::set<std::string> processedFingerprints_;

    std::size_t duplicateCount_ = 0;

    void addIndex(
        const std::string& field,
        const std::string& value,
        const std::string& eventId
    ) {
        indexes_[field][value].insert(eventId);
    }

    bool validTransition(
        AlertStatus current,
        AlertStatus next
    ) const {
        switch (current) {
            case AlertStatus::NEW:
                return next == AlertStatus::ACKNOWLEDGED ||
                       next == AlertStatus::FALSE_POSITIVE;

            case AlertStatus::ACKNOWLEDGED:
                return next == AlertStatus::INVESTIGATING ||
                       next == AlertStatus::RESOLVED ||
                       next == AlertStatus::FALSE_POSITIVE;

            case AlertStatus::INVESTIGATING:
                return next == AlertStatus::RESOLVED ||
                       next == AlertStatus::FALSE_POSITIVE;

            case AlertStatus::RESOLVED:
            case AlertStatus::FALSE_POSITIVE:
                return false;
        }

        return false;
    }

public:
    bool ingest(const SecurityEvent& event) {
        event.validate();

        if (events_.find(event.id) != events_.end()) {
            ++duplicateCount_;
            return false;
        }

        events_.emplace(event.id, event);

        addIndex("source", event.source, event.id);
        addIndex("category", toString(event.category), event.id);
        addIndex("event_type", event.eventType, event.id);
        addIndex("severity", toString(event.severity), event.id);

        for (const auto& [key, value] : event.fields) {
            addIndex(key, value, event.id);
        }

        return true;
    }

    SearchResult search(const SearchQuery& query) const {
        if (query.limit == 0 || query.limit > 100000) {
            throw std::invalid_argument("Invalid search limit");
        }

        if (query.startTime > query.endTime) {
            throw std::invalid_argument("Invalid time range");
        }

        auto started = std::chrono::steady_clock::now();

        std::unordered_set<std::string> candidates;

        if (!query.field.empty()) {
            auto fieldIt = indexes_.find(query.field);

            if (fieldIt != indexes_.end()) {
                auto valueIt = fieldIt->second.find(query.value);

                if (valueIt != fieldIt->second.end()) {
                    candidates = valueIt->second;
                }
            }
        } else {
            for (const auto& [id, event] : events_) {
                (void)event;
                candidates.insert(id);
            }
        }

        SearchResult result;

        for (const auto& id : candidates) {
            const auto& event = events_.at(id);

            if (event.timestamp < query.startTime ||
                event.timestamp > query.endTime) {
                continue;
            }

            if (!query.field.empty() &&
                event.getField(query.field) != query.value) {
                continue;
            }

            result.events.push_back(event);
        }

        result.total = result.events.size();

        std::sort(
            result.events.begin(),
            result.events.end(),
            [](const SecurityEvent& a, const SecurityEvent& b) {
                if (a.timestamp != b.timestamp) {
                    return a.timestamp > b.timestamp;
                }
                return a.id < b.id;
            }
        );

        if (result.events.size() > query.limit) {
            result.events.resize(query.limit);
        }

        auto finished = std::chrono::steady_clock::now();

        result.executionMilliseconds =
            std::chrono::duration<double, std::milli>(
                finished - started
            ).count();

        return result;
    }

    void addRule(const CorrelationRule& rule) {
        rule.validate();

        if (rules_.find(rule.id) != rules_.end()) {
            throw std::invalid_argument("Duplicate correlation rule");
        }

        rules_.emplace(rule.id, rule);
    }

    std::vector<Alert> correlate(std::int64_t now) {
        std::vector<Alert> generated;

        for (const auto& [ruleId, rule] : rules_) {
            SearchQuery query;

            query.field = "event_type";
            query.value = rule.eventType;
            query.startTime = now - rule.windowSeconds;
            query.endTime = now;
            query.limit = 100000;

            auto result = search(query);

            std::map<std::string, std::vector<std::string>> groups;

            for (const auto& event : result.events) {
                std::string key = event.getField(rule.groupField);

                if (!key.empty()) {
                    groups[key].push_back(event.id);
                }
            }

            const std::int64_t bucket = now / rule.windowSeconds;

            for (auto& [groupKey, eventIds] : groups) {
                if (eventIds.size() < rule.threshold) {
                    continue;
                }

                const std::string fingerprint =
                    ruleId + "|" + groupKey + "|" +
                    std::to_string(bucket);

                if (processedFingerprints_.count(fingerprint)) {
                    continue;
                }

                // Deterministic FNV-style hash for demonstration.
                // Production deployments should use a cryptographic hash.
                std::uint64_t hash = 14695981039346656037ULL;

                for (unsigned char c : fingerprint) {
                    hash ^= c;
                    hash *= 1099511628211ULL;
                }

                std::ostringstream idStream;
                idStream << std::hex << hash;

                std::sort(eventIds.begin(), eventIds.end());

                Alert alert;
                alert.id = idStream.str();
                alert.ruleId = rule.id;
                alert.title = rule.name;
                alert.description =
                    std::to_string(eventIds.size()) +
                    " matching events for " +
                    rule.groupField + "=" + groupKey;

                alert.severity = rule.severity;
                alert.status = AlertStatus::NEW;
                alert.createdAt = now;
                alert.eventIds = eventIds;
                alert.assignedTo = "";

                alerts_.emplace(alert.id, alert);
                processedFingerprints_.insert(fingerprint);

                generated.push_back(alert);
            }
        }

        return generated;
    }

    void transitionAlert(
        const std::string& alertId,
        AlertStatus next,
        const std::string& analyst = ""
    ) {
        auto it = alerts_.find(alertId);

        if (it == alerts_.end()) {
            throw std::invalid_argument("Alert not found");
        }

        if (!validTransition(it->second.status, next)) {
            throw std::invalid_argument("Invalid alert transition");
        }

        if (!analyst.empty()) {
            if (analyst.size() > 100) {
                throw std::invalid_argument("Analyst identity too long");
            }

            it->second.assignedTo = analyst;
        }

        it->second.status = next;
    }

    const std::unordered_map<std::string, Alert>& alerts() const {
        return alerts_;
    }

    void printStatistics() const {
        std::map<std::string, std::size_t> categories;
        std::map<std::string, std::size_t> severities;

        for (const auto& [id, event] : events_) {
            (void)id;
            ++categories[toString(event.category)];
            ++severities[toString(event.severity)];
        }

        std::cout << "\n=== SIEM STATISTICS ===\n";
        std::cout << "Events: " << events_.size() << '\n';
        std::cout << "Alerts: " << alerts_.size() << '\n';
        std::cout << "Duplicates: " << duplicateCount_ << '\n';

        std::cout << "\nCategory distribution:\n";

        for (const auto& [name, count] : categories) {
            std::cout << name << ": " << count << '\n';
        }

        std::cout << "\nSeverity distribution:\n";

        for (const auto& [name, count] : severities) {
            std::cout << name << ": " << count << '\n';
        }
    }
};


SecurityEvent createEvent(
    const std::string& id,
    std::int64_t timestamp,
    const std::string& eventType,
    const std::string& sourceIp
) {
    SecurityEvent event;

    event.id = id;
    event.timestamp = timestamp;
    event.source = "linux-auth-01";
    event.category = Category::AUTHENTICATION;
    event.eventType = eventType;
    event.severity = Severity::MEDIUM;

    event.fields = {
        {"src_ip", sourceIp},
        {"username", "admin"},
        {"host", "server-01"},
        {"protocol", "ssh"},
        {"result", "failure"}
    };

    return event;
}


int main() {
    try {
        SIEMEngine siem;

        const std::int64_t base = 1795500000;

        for (int i = 0; i < 6; ++i) {
            siem.ingest(createEvent(
                "AUTH-" + std::to_string(i + 1),
                base + i * 5,
                "failed_login",
                "203.0.113.45"
            ));
        }

        SecurityEvent firewall;
        firewall.id = "FW-001";
        firewall.timestamp = base + 30;
        firewall.source = "firewall-01";
        firewall.category = Category::FIREWALL;
        firewall.eventType = "blocked_connection";
        firewall.severity = Severity::HIGH;
        firewall.fields = {
            {"src_ip", "203.0.113.45"},
            {"dst_ip", "10.0.0.10"},
            {"dst_port", "22"},
            {"action", "blocked"}
        };

        siem.ingest(firewall);

        // Duplicate ingestion must not create a second event.
        if (siem.ingest(firewall)) {
            throw std::runtime_error("Deduplication failed");
        }

        CorrelationRule bruteForce{
            "RULE-001",
            "SSH Brute Force",
            "failed_login",
            "src_ip",
            300,
            5,
            Severity::CRITICAL
        };

        siem.addRule(bruteForce);

        SearchQuery query;
        query.field = "src_ip";
        query.value = "203.0.113.45";
        query.startTime = base - 100;
        query.endTime = base + 300;
        query.limit = 100;

        auto results = siem.search(query);

        std::cout << "=== SEARCH RESULTS ===\n";
        std::cout << "Total matching events: "
                  << results.total << '\n';

        std::cout << "Search time: "
                  << std::fixed << std::setprecision(3)
                  << results.executionMilliseconds
                  << " ms\n";

        for (const auto& event : results.events) {
            std::cout << event.id
                      << " | " << event.eventType
                      << " | " << event.getField("src_ip")
                      << " | " << toString(event.severity)
                      << '\n';
        }

        auto alerts = siem.correlate(base + 60);

        std::cout << "\n=== CORRELATION ALERTS ===\n";

        for (const auto& alert : alerts) {
            std::cout << "Alert: " << alert.id << '\n';
            std::cout << "Rule: " << alert.ruleId << '\n';
            std::cout << "Title: " << alert.title << '\n';
            std::cout << "Severity: "
                      << toString(alert.severity) << '\n';
            std::cout << "Events: "
                      << alert.eventIds.size() << '\n';

            siem.transitionAlert(
                alert.id,
                AlertStatus::ACKNOWLEDGED,
                "soc-analyst-01"
            );

            siem.transitionAlert(
                alert.id,
                AlertStatus::INVESTIGATING
            );
        }

        // Verify repeated evaluation does not create another alert.
        auto repeated = siem.correlate(base + 60);

        if (!repeated.empty()) {
            throw std::runtime_error(
                "Correlation idempotency test failed"
            );
        }

        // Verify invalid state transitions are rejected.
        if (!alerts.empty()) {
            bool rejected = false;

            try {
                siem.transitionAlert(
                    alerts.front().id,
                    AlertStatus::NEW
                );
            } catch (const std::invalid_argument&) {
                rejected = true;
            }

            if (!rejected) {
                throw std::runtime_error(
                    "Invalid alert transition was accepted"
                );
            }
        }

        siem.printStatistics();

        std::cout << "\nAll SIEM checks passed.\n";
    }
    catch (const std::exception& error) {
        std::cerr << "SIEM ERROR: "
                  << error.what() << '\n';
        return 1;
    }

    return 0;
}
