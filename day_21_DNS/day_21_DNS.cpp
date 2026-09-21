#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/*
 * DNS Technical Case Study
 *
 * Scenario:
 *   A company operates a small internal service platform. Applications ask
 *   for hostnames such as api.corp.example and database.corp.example.
 *
 * Goal:
 *   Build an educational recursive DNS resolver model that:
 *
 *     Client
 *       |
 *       v
 *     Recursive Resolver
 *       |
 *       +----> Root
 *       |
 *       +----> TLD
 *       |
 *       +----> Authoritative Server
 *
 * The implementation demonstrates:
 *   - DNS record modeling
 *   - zones
 *   - authoritative servers
 *   - recursive resolution
 *   - referrals
 *   - CNAME processing
 *   - TTL-based caching
 *   - negative responses
 *   - validation
 *   - transaction IDs
 *   - DNS header flags
 *   - a compact wire-format query builder
 *   - statistics
 *   - performance considerations
 *   - failure handling
 *
 * Compile:
 *   g++ -std=c++17 -O2 dns_case_study.cpp -o dns_case_study
 *
 * Run:
 *   ./dns_case_study
 */

namespace dns {

// ---------------------------------------------------------------------------
// Basic helpers
// ---------------------------------------------------------------------------

std::string normalizeDomain(std::string name) {
    if (name.empty()) {
        return name;
    }

    // DNS names are case-insensitive.
    std::transform(
        name.begin(),
        name.end(),
        name.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        }
    );

    // Presentation-form fully qualified names can end with a root dot.
    if (name.size() > 1 && name.back() == '.') {
        name.pop_back();
    }

    return name;
}

std::vector<std::string> splitLabels(const std::string& name) {
    std::vector<std::string> labels;
    const std::string normalized = normalizeDomain(name);

    if (normalized.empty()) {
        return labels;
    }

    std::stringstream stream(normalized);
    std::string label;

    while (std::getline(stream, label, '.')) {
        labels.push_back(label);
    }

    return labels;
}

bool validHostname(const std::string& name) {
    const std::string normalized = normalizeDomain(name);

    if (normalized.empty() || normalized.size() > 253) {
        return false;
    }

    for (const std::string& label : splitLabels(normalized)) {
        if (label.empty() || label.size() > 63) {
            return false;
        }

        if (label.front() == '-' || label.back() == '-') {
            return false;
        }

        for (unsigned char character : label) {
            const bool allowed =
                std::isalnum(character) || character == '-';

            if (!allowed) {
                return false;
            }
        }
    }

    return true;
}


// ---------------------------------------------------------------------------
// DNS record model
// ---------------------------------------------------------------------------

enum class RecordType {
    A,
    AAAA,
    CNAME,
    NS,
    MX,
    TXT,
    SOA
};

std::string recordTypeToString(RecordType type) {
    switch (type) {
        case RecordType::A: return "A";
        case RecordType::AAAA: return "AAAA";
        case RecordType::CNAME: return "CNAME";
        case RecordType::NS: return "NS";
        case RecordType::MX: return "MX";
        case RecordType::TXT: return "TXT";
        case RecordType::SOA: return "SOA";
    }

    return "UNKNOWN";
}

struct DNSRecord {
    std::string name;
    RecordType type;
    std::string value;
    std::uint32_t ttl;

    DNSRecord(
        std::string recordName,
        RecordType recordType,
        std::string recordValue,
        std::uint32_t recordTTL
    )
        : name(normalizeDomain(std::move(recordName))),
          type(recordType),
          value(std::move(recordValue)),
          ttl(recordTTL) {}
};


// ---------------------------------------------------------------------------
// DNS zone
// ---------------------------------------------------------------------------

class DNSZone {
private:
    std::string zoneName;

    using Key = std::pair<std::string, RecordType>;

    struct KeyComparator {
        bool operator()(const Key& left, const Key& right) const {
            if (left.first != right.first) {
                return left.first < right.first;
            }

            return static_cast<int>(left.second)
                < static_cast<int>(right.second);
        }
    };

    std::map<Key, std::vector<DNSRecord>, KeyComparator> records;

public:
    explicit DNSZone(std::string name)
        : zoneName(normalizeDomain(std::move(name))) {}

    const std::string& name() const {
        return zoneName;
    }

    void addRecord(const DNSRecord& record) {
        const auto key = std::make_pair(
            normalizeDomain(record.name),
            record.type
        );

        records[key].push_back(record);
    }

    std::vector<DNSRecord> lookup(
        const std::string& name,
        RecordType type
    ) const {
        const auto key = std::make_pair(
            normalizeDomain(name),
            type
        );

        const auto iterator = records.find(key);

        if (iterator == records.end()) {
            return {};
        }

        return iterator->second;
    }
};


// ---------------------------------------------------------------------------
// Authoritative server
// ---------------------------------------------------------------------------

class AuthoritativeServer {
private:
    std::string serverName;
    std::vector<DNSZone> zones;

    bool belongsToZone(
        const std::string& queryName,
        const std::string& zoneName
    ) const {
        const std::string query = normalizeDomain(queryName);
        const std::string zone = normalizeDomain(zoneName);

        if (zone == ".") {
            return true;
        }

        return query == zone ||
               (
                   query.size() > zone.size() &&
                   query.compare(
                       query.size() - zone.size(),
                       zone.size(),
                       zone
                   ) == 0 &&
                   query[query.size() - zone.size() - 1] == '.'
               );
    }

public:
    explicit AuthoritativeServer(std::string name)
        : serverName(std::move(name)) {}

    void addZone(const DNSZone& zone) {
        zones.push_back(zone);
    }

    const std::string& name() const {
        return serverName;
    }

    std::optional<std::reference_wrapper<const DNSZone>>
    findBestZone(const std::string& queryName) const {
        const DNSZone* best = nullptr;

        for (const DNSZone& zone : zones) {
            if (!belongsToZone(queryName, zone.name())) {
                continue;
            }

            if (
                best == nullptr ||
                zone.name().size() > best->name().size()
            ) {
                best = &zone;
            }
        }

        if (best == nullptr) {
            return std::nullopt;
        }

        return std::cref(*best);
    }

    std::vector<DNSRecord> query(
        const std::string& name,
        RecordType type
    ) const {
        const auto zone = findBestZone(name);

        if (!zone.has_value()) {
            return {};
        }

        return zone->get().lookup(name, type);
    }
};


// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

struct CacheEntry {
    std::vector<DNSRecord> records;
    std::chrono::steady_clock::time_point expiresAt;
};

class DNSCache {
private:
    std::size_t capacity;
    std::map<
        std::pair<std::string, RecordType>,
        CacheEntry
    > entries;

    std::size_t hits = 0;
    std::size_t misses = 0;

public:
    explicit DNSCache(std::size_t cacheCapacity)
        : capacity(cacheCapacity) {
        if (capacity == 0) {
            throw std::invalid_argument(
                "DNS cache capacity must be greater than zero."
            );
        }
    }

    std::optional<std::vector<DNSRecord>> get(
        const std::string& name,
        RecordType type,
        std::chrono::steady_clock::time_point now
    ) {
        const auto key = std::make_pair(
            normalizeDomain(name),
            type
        );

        auto iterator = entries.find(key);

        if (iterator == entries.end()) {
            ++misses;
            return std::nullopt;
        }

        if (now >= iterator->second.expiresAt) {
            entries.erase(iterator);
            ++misses;
            return std::nullopt;
        }

        ++hits;
        return iterator->second.records;
    }

    void put(
        const std::string& name,
        RecordType type,
        const std::vector<DNSRecord>& records,
        std::chrono::steady_clock::time_point now
    ) {
        if (records.empty()) {
            return;
        }

        const auto key = std::make_pair(
            normalizeDomain(name),
            type
        );

        if (entries.size() >= capacity && entries.find(key) == entries.end()) {
            // Educational eviction policy:
            // remove the entry that expires first.
            auto oldest = std::min_element(
                entries.begin(),
                entries.end(),
                [](const auto& left, const auto& right) {
                    return left.second.expiresAt < right.second.expiresAt;
                }
            );

            if (oldest != entries.end()) {
                entries.erase(oldest);
            }
        }

        std::uint32_t ttl = records.front().ttl;

        for (const DNSRecord& record : records) {
            ttl = std::min(ttl, record.ttl);
        }

        entries[key] = CacheEntry{
            records,
            now + std::chrono::seconds(ttl)
        };
    }

    std::size_t hitsCount() const {
        return hits;
    }

    std::size_t missesCount() const {
        return misses;
    }

    double hitRate() const {
        const std::size_t total = hits + misses;

        if (total == 0) {
            return 0.0;
        }

        return static_cast<double>(hits) /
               static_cast<double>(total);
    }

    std::size_t size() const {
        return entries.size();
    }
};


// ---------------------------------------------------------------------------
// Resolver result
// ---------------------------------------------------------------------------

enum class ResolutionStatus {
    NOERROR,
    NXDOMAIN,
    SERVFAIL
};

std::string statusToString(ResolutionStatus status) {
    switch (status) {
        case ResolutionStatus::NOERROR: return "NOERROR";
        case ResolutionStatus::NXDOMAIN: return "NXDOMAIN";
        case ResolutionStatus::SERVFAIL: return "SERVFAIL";
    }

    return "UNKNOWN";
}

struct ResolutionResult {
    ResolutionStatus status;
    std::vector<DNSRecord> records;
    bool cacheHit;
    std::vector<std::string> path;
    std::string explanation;
};


// ---------------------------------------------------------------------------
// Recursive resolver
// ---------------------------------------------------------------------------

class RecursiveResolver {
private:
    const AuthoritativeServer& rootServer;
    const AuthoritativeServer& tldServer;
    const AuthoritativeServer& authoritativeServer;

    DNSCache cache;

public:
    RecursiveResolver(
        const AuthoritativeServer& root,
        const AuthoritativeServer& tld,
        const AuthoritativeServer& authoritative,
        std::size_t cacheCapacity
    )
        : rootServer(root),
          tldServer(tld),
          authoritativeServer(authoritative),
          cache(cacheCapacity) {}

    ResolutionResult resolve(
        const std::string& queryName,
        RecordType queryType,
        std::chrono::steady_clock::time_point now
    ) {
        const std::string normalizedName =
            normalizeDomain(queryName);

        if (!validHostname(normalizedName)) {
            return {
                ResolutionStatus::SERVFAIL,
                {},
                false,
                {"Client", "Recursive Resolver"},
                "Invalid hostname syntax."
            };
        }

        const auto cached = cache.get(
            normalizedName,
            queryType,
            now
        );

        if (cached.has_value()) {
            return {
                ResolutionStatus::NOERROR,
                cached.value(),
                true,
                {
                    "Client",
                    "Recursive Resolver",
                    "Cache"
                },
                "Answer served from cache."
            };
        }

        const std::vector<std::string> path{
            "Client",
            "Recursive Resolver",
            "Root Server",
            "COM TLD Server",
            "Authoritative Server"
        };

        // Root referral.
        const auto rootReferral =
            rootServer.query("com", RecordType::NS);

        if (rootReferral.empty()) {
            return {
                ResolutionStatus::SERVFAIL,
                {},
                false,
                path,
                "Root server did not provide a TLD referral."
            };
        }

        // TLD referral.
        const auto tldReferral =
            tldServer.query("example.com", RecordType::NS);

        if (tldReferral.empty()) {
            return {
                ResolutionStatus::SERVFAIL,
                {},
                false,
                path,
                "TLD server did not provide an authoritative referral."
            };
        }

        // Ask the authoritative server for the requested type.
        auto records = authoritativeServer.query(
            normalizedName,
            queryType
        );

        // For A and AAAA requests, follow a CNAME when necessary.
        if (
            records.empty() &&
            (
                queryType == RecordType::A ||
                queryType == RecordType::AAAA
            )
        ) {
            const auto aliases = authoritativeServer.query(
                normalizedName,
                RecordType::CNAME
            );

            if (!aliases.empty()) {
                const std::string target =
                    normalizeDomain(aliases.front().value);

                records = authoritativeServer.query(
                    target,
                    queryType
                );
            }
        }

        if (records.empty()) {
            return {
                ResolutionStatus::NXDOMAIN,
                {},
                false,
                path,
                "No matching record was found in the simulated zone."
            };
        }

        cache.put(
            normalizedName,
            queryType,
            records,
            now
        );

        return {
            ResolutionStatus::NOERROR,
            records,
            false,
            path,
            "Answer obtained through recursive resolution."
        };
    }

    const DNSCache& cacheStatistics() const {
        return cache;
    }
};


// ---------------------------------------------------------------------------
// DNS wire-format helpers
// ---------------------------------------------------------------------------

std::uint16_t dnsTypeCode(RecordType type) {
    switch (type) {
        case RecordType::A: return 1;
        case RecordType::NS: return 2;
        case RecordType::CNAME: return 5;
        case RecordType::SOA: return 6;
        case RecordType::MX: return 15;
        case RecordType::TXT: return 16;
        case RecordType::AAAA: return 28;
    }

    return 0;
}

void appendUInt16(
    std::vector<std::uint8_t>& output,
    std::uint16_t value
) {
    output.push_back(
        static_cast<std::uint8_t>((value >> 8) & 0xFF)
    );
    output.push_back(
        static_cast<std::uint8_t>(value & 0xFF)
    );
}

std::vector<std::uint8_t> encodeDnsName(
    const std::string& name
) {
    const std::string normalized = normalizeDomain(name);

    if (normalized.empty()) {
        return {0};
    }

    std::vector<std::uint8_t> output;

    for (const std::string& label : splitLabels(normalized)) {
        if (label.size() > 63) {
            throw std::invalid_argument(
                "DNS label cannot exceed 63 octets."
            );
        }

        output.push_back(
            static_cast<std::uint8_t>(label.size())
        );

        for (unsigned char character : label) {
            output.push_back(character);
        }
    }

    output.push_back(0);
    return output;
}

std::vector<std::uint8_t> buildDnsQuery(
    std::uint16_t transactionId,
    const std::string& name,
    RecordType type
) {
    const std::uint16_t flags = 0x0100; // RD=1

    std::vector<std::uint8_t> packet;
    packet.reserve(64);

    appendUInt16(packet, transactionId);
    appendUInt16(packet, flags);

    // QDCOUNT = 1.
    appendUInt16(packet, 1);

    // ANCOUNT, NSCOUNT, ARCOUNT.
    appendUInt16(packet, 0);
    appendUInt16(packet, 0);
    appendUInt16(packet, 0);

    const auto encodedName = encodeDnsName(name);

    packet.insert(
        packet.end(),
        encodedName.begin(),
        encodedName.end()
    );

    appendUInt16(packet, dnsTypeCode(type));
    appendUInt16(packet, 1); // QCLASS = IN

    return packet;
}

std::string bytesToHex(
    const std::vector<std::uint8_t>& bytes
) {
    std::ostringstream output;

    output << std::hex
           << std::setfill('0');

    for (std::uint8_t byte : bytes) {
        output << std::setw(2)
               << static_cast<unsigned int>(byte)
               << ' ';
    }

    return output.str();
}


// ---------------------------------------------------------------------------
// DNS infrastructure construction
// ---------------------------------------------------------------------------

struct Infrastructure {
    AuthoritativeServer root;
    AuthoritativeServer tld;
    AuthoritativeServer authoritative;

    Infrastructure()
        : root("Root Server"),
          tld("COM TLD Server"),
          authoritative("ns1.example.com") {

        DNSZone rootZone(".");
        rootZone.addRecord(
            DNSRecord(
                "com",
                RecordType::NS,
                "a.gtld-servers.net.",
                172800
            )
        );

        DNSZone comZone("com");
        comZone.addRecord(
            DNSRecord(
                "example.com",
                RecordType::NS,
                "ns1.example.com.",
                86400
            )
        );

        DNSZone exampleZone("example.com");

        exampleZone.addRecord(
            DNSRecord(
                "example.com",
                RecordType::A,
                "93.184.216.34",
                300
            )
        );

        exampleZone.addRecord(
            DNSRecord(
                "example.com",
                RecordType::AAAA,
                "2001:db8::10",
                300
            )
        );

        exampleZone.addRecord(
            DNSRecord(
                "www.example.com",
                RecordType::CNAME,
                "example.com.",
                300
            )
        );

        exampleZone.addRecord(
            DNSRecord(
                "api.example.com",
                RecordType::A,
                "192.0.2.50",
                60
            )
        );

        exampleZone.addRecord(
            DNSRecord(
                "mail.example.com",
                RecordType::A,
                "192.0.2.25",
                300
            )
        );

        exampleZone.addRecord(
            DNSRecord(
                "example.com",
                RecordType::MX,
                "10 mail.example.com.",
                3600
            )
        );

        root.addZone(rootZone);
        tld.addZone(comZone);
        authoritative.addZone(exampleZone);
    }
};


// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

void printRecords(
    const std::vector<DNSRecord>& records
) {
    if (records.empty()) {
        std::cout << "  No records\n";
        return;
    }

    for (const DNSRecord& record : records) {
        std::cout
            << "  "
            << std::left
            << std::setw(28)
            << record.name
            << std::setw(6)
            << record.ttl
            << std::setw(8)
            << recordTypeToString(record.type)
            << record.value
            << '\n';
    }
}

void printResolution(
    const std::string& name,
    RecordType type,
    const ResolutionResult& result
) {
    std::cout << "\nQuery: "
              << name
              << " "
              << recordTypeToString(type)
              << '\n';

    std::cout << "Status: "
              << statusToString(result.status)
              << '\n';

    std::cout << "Cache hit: "
              << (result.cacheHit ? "yes" : "no")
              << '\n';

    std::cout << "Path:\n";

    for (const std::string& step : result.path) {
        std::cout << "  -> " << step << '\n';
    }

    std::cout << "Answer:\n";
    printRecords(result.records);

    std::cout << "Explanation: "
              << result.explanation
              << '\n';
}


// ---------------------------------------------------------------------------
// Demonstrations
// ---------------------------------------------------------------------------

void demonstrateRecordTypes() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "1. DNS RECORD TYPES\n"
        << "==============================================================\n";

    std::vector<DNSRecord> records{
        DNSRecord(
            "example.com",
            RecordType::A,
            "93.184.216.34",
            300
        ),
        DNSRecord(
            "example.com",
            RecordType::AAAA,
            "2001:db8::10",
            300
        ),
        DNSRecord(
            "www.example.com",
            RecordType::CNAME,
            "example.com.",
            300
        ),
        DNSRecord(
            "example.com",
            RecordType::MX,
            "10 mail.example.com.",
            3600
        ),
        DNSRecord(
            "example.com",
            RecordType::NS,
            "ns1.example.com.",
            86400
        ),
        DNSRecord(
            "example.com",
            RecordType::TXT,
            "v=spf1 -all",
            3600
        )
    };

    printRecords(records);
}

void demonstrateResolution() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "2. RECURSIVE RESOLUTION\n"
        << "==============================================================\n";

    Infrastructure infrastructure;

    RecursiveResolver resolver(
        infrastructure.root,
        infrastructure.tld,
        infrastructure.authoritative,
        100
    );

    const auto now =
        std::chrono::steady_clock::now();

    const auto first = resolver.resolve(
        "example.com",
        RecordType::A,
        now
    );

    printResolution(
        "example.com",
        RecordType::A,
        first
    );

    const auto second = resolver.resolve(
        "example.com",
        RecordType::A,
        now
    );

    printResolution(
        "example.com",
        RecordType::A,
        second
    );
}

void demonstrateCname() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "3. CNAME PROCESSING\n"
        << "==============================================================\n";

    Infrastructure infrastructure;

    RecursiveResolver resolver(
        infrastructure.root,
        infrastructure.tld,
        infrastructure.authoritative,
        100
    );

    const auto result = resolver.resolve(
        "www.example.com",
        RecordType::A,
        std::chrono::steady_clock::now()
    );

    printResolution(
        "www.example.com",
        RecordType::A,
        result
    );
}

void demonstrateFailures() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "4. FAILURE CONDITIONS\n"
        << "==============================================================\n";

    Infrastructure infrastructure;

    RecursiveResolver resolver(
        infrastructure.root,
        infrastructure.tld,
        infrastructure.authoritative,
        100
    );

    const auto now =
        std::chrono::steady_clock::now();

    const auto missing = resolver.resolve(
        "missing.example.com",
        RecordType::A,
        now
    );

    printResolution(
        "missing.example.com",
        RecordType::A,
        missing
    );

    const auto invalid = resolver.resolve(
        "-invalid.example.com",
        RecordType::A,
        now
    );

    printResolution(
        "-invalid.example.com",
        RecordType::A,
        invalid
    );
}

void demonstrateTTL() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "5. TTL BEHAVIOR\n"
        << "==============================================================\n";

    Infrastructure infrastructure;

    RecursiveResolver resolver(
        infrastructure.root,
        infrastructure.tld,
        infrastructure.authoritative,
        100
    );

    const auto start =
        std::chrono::steady_clock::now();

    const auto first = resolver.resolve(
        "api.example.com",
        RecordType::A,
        start
    );

    std::cout
        << "Initial query cache hit: "
        << (first.cacheHit ? "yes" : "no")
        << '\n';

    const auto beforeExpiry =
        start + std::chrono::seconds(59);

    const auto second = resolver.resolve(
        "api.example.com",
        RecordType::A,
        beforeExpiry
    );

    std::cout
        << "At +59 seconds cache hit: "
        << (second.cacheHit ? "yes" : "no")
        << '\n';

    const auto afterExpiry =
        start + std::chrono::seconds(60);

    const auto third = resolver.resolve(
        "api.example.com",
        RecordType::A,
        afterExpiry
    );

    std::cout
        << "At +60 seconds cache hit: "
        << (third.cacheHit ? "yes" : "no")
        << '\n';

    std::cout
        << "The simulated api.example.com record has a 60-second TTL.\n";
}

void demonstrateWireFormat() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "6. DNS WIRE-FORMAT QUERY\n"
        << "==============================================================\n";

    const auto packet = buildDnsQuery(
        0x1234,
        "example.com",
        RecordType::A
    );

    std::cout
        << "Transaction ID: 0x1234\n"
        << "Flags: 0x0100 (Recursion Desired)\n"
        << "Question count: 1\n"
        << "Packet bytes:\n"
        << bytesToHex(packet)
        << '\n';

    std::cout
        << "\nThe packet consists of:\n"
        << "  Header\n"
        << "  QNAME\n"
        << "  QTYPE\n"
        << "  QCLASS\n";
}

void demonstrateArchitecture() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "7. ARCHITECTURE\n"
        << "==============================================================\n";

    std::cout
        << R"(
Application
    |
    | asks for api.example.com
    v
Recursive Resolver
    |
    +--> Cache
    |
    +--> Root
    |       |
    |       +--> referral to .com infrastructure
    |
    +--> TLD
    |       |
    |       +--> referral to example.com authoritative server
    |
    +--> Authoritative Server
            |
            +--> A / AAAA / CNAME / MX / NS / TXT

The important architectural boundary is that the client does not normally
need to know how the entire DNS hierarchy is traversed. The recursive
resolver performs that work and caches useful results.
)"
        << '\n';
}

void demonstrateComplexity() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "8. PERFORMANCE AND COMPLEXITY\n"
        << "==============================================================\n";

    std::cout
        << "The cache uses std::map in this implementation.\n"
        << "Typical lookup complexity: O(log n).\n"
        << "Insertion complexity: O(log n).\n"
        << "Eviction search: O(n) because the earliest-expiring entry is found\n"
        << "by scanning the cache.\n\n"
        << "A production resolver can use specialized structures to make cache\n"
        << "operations faster, reduce lock contention, and handle large query\n"
        << "volumes. Real network latency usually dominates a simple in-memory\n"
        << "lookup, so caching is a major performance mechanism.\n";
}

void demonstrateSecurity() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "9. SECURITY CONSIDERATIONS\n"
        << "==============================================================\n";

    std::cout
        << "Cache poisoning:\n"
        << "  False records may be inserted into resolver caches.\n\n"
        << "DNSSEC:\n"
        << "  Cryptographic signatures allow validating resolvers to verify DNS\n"
        << "  data and its chain of trust.\n\n"
        << "DNS over TLS / HTTPS:\n"
        << "  Encrypt DNS transport between the client and resolver.\n\n"
        << "Open resolvers:\n"
        << "  Poorly controlled recursive services can be abused for reflection\n"
        << "  and amplification attacks.\n\n"
        << "Input validation:\n"
        << "  Network-facing DNS software must carefully validate packet lengths,\n"
        << "  labels, compression pointers, record counts, and resource limits.\n";
}

void runTests() {
    std::cout
        << "\n"
        << "==============================================================\n"
        << "10. TESTS\n"
        << "==============================================================\n";

    if (normalizeDomain("Example.COM.") != "example.com") {
        throw std::runtime_error("Domain normalization test failed.");
    }

    if (!validHostname("example.com")) {
        throw std::runtime_error("Valid hostname test failed.");
    }

    if (validHostname("-bad.example.com")) {
        throw std::runtime_error("Invalid hostname test failed.");
    }

    const auto encoded =
        encodeDnsName("example.com");

    if (
        encoded.size() != 13 ||
        encoded[0] != 7 ||
        encoded[8] != 3 ||
        encoded.back() != 0
    ) {
        throw std::runtime_error(
            "DNS name wire-format test failed."
        );
    }

    const auto packet =
        buildDnsQuery(
            0xABCD,
            "example.com",
            RecordType::A
        );

    if (
        packet.size() < 12 ||
        packet[0] != 0xAB ||
        packet[1] != 0xCD
    ) {
        throw std::runtime_error(
            "DNS transaction-ID test failed."
        );
    }

    Infrastructure infrastructure;

    RecursiveResolver resolver(
        infrastructure.root,
        infrastructure.tld,
        infrastructure.authoritative,
        10
    );

    const auto now =
        std::chrono::steady_clock::now();

    const auto first =
        resolver.resolve(
            "example.com",
            RecordType::A,
            now
        );

    if (
        first.status != ResolutionStatus::NOERROR ||
        first.records.empty() ||
        first.records.front().value != "93.184.216.34"
    ) {
        throw std::runtime_error(
            "Recursive resolution test failed."
        );
    }

    const auto second =
        resolver.resolve(
            "example.com",
            RecordType::A,
            now
        );

    if (!second.cacheHit) {
        throw std::runtime_error(
            "Cache test failed."
        );
    }

    const auto missing =
        resolver.resolve(
            "does-not-exist.example.com",
            RecordType::A,
            now
        );

    if (missing.status != ResolutionStatus::NXDOMAIN) {
        throw std::runtime_error(
            "NXDOMAIN test failed."
        );
    }

    std::cout << "All tests passed.\n";
}

} // namespace dns


// ---------------------------------------------------------------------------
// Program entry point
// ---------------------------------------------------------------------------

int main() {
    try {
        std::cout
            << "==============================================================\n"
            << "DNS INDUSTRY-STYLE TECHNICAL CASE STUDY\n"
            << "==============================================================\n"
            << "Scenario: internal application DNS resolution with recursive\n"
            << "resolution, authoritative zones, CNAME processing, and caching.\n";

        dns::demonstrateRecordTypes();
        dns::demonstrateArchitecture();
        dns::demonstrateResolution();
        dns::demonstrateCname();
        dns::demonstrateFailures();
        dns::demonstrateTTL();
        dns::demonstrateWireFormat();
        dns::demonstrateComplexity();
        dns::demonstrateSecurity();
        dns::runTests();

        std::cout
            << "\n==============================================================\n"
            << "CASE STUDY COMPLETE\n"
            << "==============================================================\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
