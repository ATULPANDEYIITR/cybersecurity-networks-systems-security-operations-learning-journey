/*
 * Advanced Nmap Defensive Scanning
 *
 * C++17 case study:
 *   A defensive service-inventory analyzer for Nmap XML output.
 *
 * The program demonstrates how an organization could process Nmap XML
 * snapshots, normalize service observations, compare a current scan with
 * an approved baseline, and produce a cautious defensive report.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -Wall -Wextra -pedantic nmap_inventory.cpp -o nmap_inventory
 *
 * Run:
 *   ./nmap_inventory
 *
 * Optional:
 *   ./nmap_inventory baseline.xml current.xml
 *
 * The program intentionally analyzes scan output rather than launching
 * arbitrary network scans. This separates potentially disruptive collection
 * from controlled offline analysis.
 */

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>


// ---------------------------------------------------------------------------
// Domain model
// ---------------------------------------------------------------------------

struct PortObservation {
    int port = 0;
    std::string protocol;
    std::string state;
    std::string service;
    std::string product;
    std::string version;
    std::map<std::string, std::string> scripts;
};


struct HostObservation {
    std::string address;
    std::string hostname;
    std::string status;
    std::vector<PortObservation> ports;
};


struct InventoryKey {
    std::string host;
    int port = 0;
    std::string protocol;

    bool operator<(const InventoryKey& other) const {
        if (host != other.host) {
            return host < other.host;
        }

        if (port != other.port) {
            return port < other.port;
        }

        return protocol < other.protocol;
    }
};


struct InventoryRecord {
    InventoryKey key;
    std::string service;
    std::string product;
    std::string version;
};


// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

std::string trim(const std::string& input) {
    std::size_t first = 0;

    while (first < input.size() &&
           std::isspace(static_cast<unsigned char>(input[first]))) {
        ++first;
    }

    std::size_t last = input.size();

    while (last > first &&
           std::isspace(static_cast<unsigned char>(input[last - 1]))) {
        --last;
    }

    return input.substr(first, last - first);
}


std::string decodeXmlEntities(std::string value) {
    struct Replacement {
        const char* encoded;
        const char* decoded;
    };

    const Replacement replacements[] = {
        {"&lt;", "<"},
        {"&gt;", ">"},
        {"&quot;", "\""},
        {"&apos;", "'"},
        {"&amp;", "&"}
    };

    for (const auto& replacement : replacements) {
        std::size_t position = 0;

        while (
            (position = value.find(
                replacement.encoded,
                position
            )) != std::string::npos
        ) {
            value.replace(
                position,
                std::string(replacement.encoded).size(),
                replacement.decoded
            );

            position += std::string(replacement.decoded).size();
        }
    }

    return value;
}


/*
 * This is a deliberately limited XML reader for controlled Nmap output.
 * It is not intended to be a general-purpose XML parser.
 *
 * Production software processing untrusted XML should use a dedicated
 * standards-compliant parser configured to disable external entities and
 * unsafe DTD processing.
 */
std::string getAttribute(
    const std::string& tag,
    const std::string& attribute
) {
    const std::string needle = attribute + "=\"";
    const std::size_t start = tag.find(needle);

    if (start == std::string::npos) {
        return "";
    }

    const std::size_t valueStart =
        start + needle.size();

    const std::size_t valueEnd =
        tag.find('"', valueStart);

    if (valueEnd == std::string::npos) {
        return "";
    }

    return decodeXmlEntities(
        tag.substr(
            valueStart,
            valueEnd - valueStart
        )
    );
}


std::vector<std::string> findElements(
    const std::string& xml,
    const std::string& element
) {
    std::vector<std::string> elements;

    const std::string opening = "<" + element;
    const std::string closing = "</" + element + ">";

    std::size_t position = 0;

    while (position < xml.size()) {
        const std::size_t start = xml.find(
            opening,
            position
        );

        if (start == std::string::npos) {
            break;
        }

        const std::size_t openingEnd =
            xml.find('>', start);

        if (openingEnd == std::string::npos) {
            break;
        }

        const bool selfClosing =
            openingEnd > start &&
            xml[openingEnd - 1] == '/';

        if (selfClosing) {
            elements.push_back(
                xml.substr(
                    start,
                    openingEnd - start + 1
                )
            );

            position = openingEnd + 1;
            continue;
        }

        const std::size_t closingStart =
            xml.find(closing, openingEnd + 1);

        if (closingStart == std::string::npos) {
            break;
        }

        const std::size_t end =
            closingStart + closing.size();

        elements.push_back(
            xml.substr(
                start,
                end - start
            )
        );

        position = end;
    }

    return elements;
}


std::string elementContent(
    const std::string& elementXml,
    const std::string& element
) {
    const std::string opening = "<" + element;
    const std::size_t start = elementXml.find(opening);

    if (start == std::string::npos) {
        return "";
    }

    const std::size_t openingEnd =
        elementXml.find('>', start);

    if (openingEnd == std::string::npos) {
        return "";
    }

    const std::string closing =
        "</" + element + ">";

    const std::size_t closingStart =
        elementXml.find(
            closing,
            openingEnd + 1
        );

    if (closingStart == std::string::npos) {
        return "";
    }

    return elementXml.substr(
        openingEnd + 1,
        closingStart - openingEnd - 1
    );
}


// ---------------------------------------------------------------------------
// Controlled Nmap XML parser
// ---------------------------------------------------------------------------

class NmapXmlParser {
public:
    std::vector<HostObservation> parse(
        const std::string& xml
    ) const {
        validateXmlSafety(xml);

        std::vector<HostObservation> hosts;

        for (const std::string& hostXml :
             findElements(xml, "host")) {
            HostObservation host;

            const auto statusElements =
                findElements(hostXml, "status");

            if (!statusElements.empty()) {
                host.status =
                    getAttribute(
                        statusElements.front(),
                        "state"
                    );
            }

            for (const std::string& addressXml :
                 findElements(hostXml, "address")) {
                const std::string type =
                    getAttribute(addressXml, "addrtype");

                if (type == "ipv4" || type == "ipv6") {
                    host.address =
                        getAttribute(addressXml, "addr");
                    break;
                }
            }

            const auto hostnameElements =
                findElements(hostXml, "hostname");

            if (!hostnameElements.empty()) {
                host.hostname =
                    getAttribute(
                        hostnameElements.front(),
                        "name"
                    );
            }

            const std::string portsXml =
                elementContent(hostXml, "ports");

            for (const std::string& portXml :
                 findElements(portsXml, "port")) {
                PortObservation port;

                const std::string portValue =
                    getAttribute(portXml, "portid");

                try {
                    port.port =
                        std::stoi(portValue);
                } catch (const std::exception&) {
                    continue;
                }

                port.protocol =
                    getAttribute(portXml, "protocol");

                const auto states =
                    findElements(portXml, "state");

                if (!states.empty()) {
                    port.state =
                        getAttribute(
                            states.front(),
                            "state"
                        );
                }

                const auto services =
                    findElements(portXml, "service");

                if (!services.empty()) {
                    port.service =
                        getAttribute(
                            services.front(),
                            "name"
                        );

                    port.product =
                        getAttribute(
                            services.front(),
                            "product"
                        );

                    port.version =
                        getAttribute(
                            services.front(),
                            "version"
                        );
                }

                for (const std::string& scriptXml :
                     findElements(portXml, "script")) {
                    const std::string id =
                        getAttribute(scriptXml, "id");

                    const std::string output =
                        getAttribute(scriptXml, "output");

                    if (!id.empty()) {
                        port.scripts[id] = output;
                    }
                }

                host.ports.push_back(port);
            }

            hosts.push_back(host);
        }

        return hosts;
    }

private:
    static void validateXmlSafety(
        const std::string& xml
    ) {
        if (xml.empty()) {
            throw std::runtime_error(
                "Nmap XML input is empty."
            );
        }

        /*
         * The simplified parser intentionally rejects DTD/entity declarations.
         * This avoids accidental acceptance of external-entity constructs.
         */
        if (
            xml.find("<!DOCTYPE") != std::string::npos ||
            xml.find("<!ENTITY") != std::string::npos
        ) {
            throw std::runtime_error(
                "DTD/entity declarations are not supported."
            );
        }
    }
};


// ---------------------------------------------------------------------------
// Inventory engine
// ---------------------------------------------------------------------------

class DefensiveInventory {
public:
    explicit DefensiveInventory(
        std::vector<HostObservation> hosts
    )
        : hosts_(std::move(hosts)) {}

    std::vector<InventoryRecord> openServices() const {
        std::vector<InventoryRecord> records;

        for (const auto& host : hosts_) {
            for (const auto& port : host.ports) {
                if (port.state != "open") {
                    continue;
                }

                InventoryRecord record;

                record.key.host = host.address;
                record.key.port = port.port;
                record.key.protocol = port.protocol;

                record.service = port.service;
                record.product = port.product;
                record.version = port.version;

                records.push_back(record);
            }
        }

        std::sort(
            records.begin(),
            records.end(),
            [](const InventoryRecord& left,
               const InventoryRecord& right) {
                return left.key < right.key;
            }
        );

        return records;
    }

    void printReport() const {
        std::cout
            << "\n"
            << "DEFENSIVE SERVICE INVENTORY\n"
            << "---------------------------\n";

        if (hosts_.empty()) {
            std::cout
                << "No hosts were recorded.\n";
            return;
        }

        for (const auto& host : hosts_) {
            std::cout
                << "\nHost: "
                << (host.hostname.empty()
                        ? host.address
                        : host.hostname)
                << "\n";

            std::cout
                << "Address: "
                << host.address
                << "\n";

            std::cout
                << "Status: "
                << host.status
                << "\n";

            if (host.ports.empty()) {
                std::cout
                    << "No port records.\n";
                continue;
            }

            for (const auto& port : host.ports) {
                std::cout
                    << "  "
                    << port.port
                    << "/"
                    << port.protocol
                    << " "
                    << port.state
                    << " "
                    << port.service;

                if (!port.product.empty()) {
                    std::cout
                        << " "
                        << port.product;
                }

                if (!port.version.empty()) {
                    std::cout
                        << " "
                        << port.version;
                }

                std::cout
                    << "\n";

                for (const auto& script :
                     port.scripts) {
                    std::cout
                        << "      NSE "
                        << script.first
                        << ": "
                        << script.second
                        << "\n";
                }
            }
        }
    }

    const std::vector<HostObservation>& hosts() const {
        return hosts_;
    }

private:
    std::vector<HostObservation> hosts_;
};


// ---------------------------------------------------------------------------
// Inventory comparison
// ---------------------------------------------------------------------------

class InventoryComparator {
public:
    struct Difference {
        std::vector<InventoryRecord> added;
        std::vector<InventoryRecord> removed;
        std::vector<std::pair<
            InventoryRecord,
            InventoryRecord
        >> changed;
    };

    static Difference compare(
        const DefensiveInventory& before,
        const DefensiveInventory& after
    ) {
        const auto beforeRecords =
            before.openServices();

        const auto afterRecords =
            after.openServices();

        std::map<InventoryKey, InventoryRecord>
            beforeMap;

        std::map<InventoryKey, InventoryRecord>
            afterMap;

        for (const auto& record : beforeRecords) {
            beforeMap[record.key] = record;
        }

        for (const auto& record : afterRecords) {
            afterMap[record.key] = record;
        }

        Difference difference;

        for (const auto& [key, record] :
             afterMap) {
            const auto old =
                beforeMap.find(key);

            if (old == beforeMap.end()) {
                difference.added.push_back(record);
                continue;
            }

            if (
                old->second.service != record.service ||
                old->second.product != record.product ||
                old->second.version != record.version
            ) {
                difference.changed.push_back({
                    old->second,
                    record
                });
            }
        }

        for (const auto& [key, record] :
             beforeMap) {
            if (afterMap.find(key) == afterMap.end()) {
                difference.removed.push_back(record);
            }
        }

        return difference;
    }

    static void print(
        const Difference& difference
    ) {
        std::cout
            << "\n"
            << "INVENTORY DIFFERENCE\n"
            << "--------------------\n";

        std::cout
            << "\nNewly observed open services:\n";

        if (difference.added.empty()) {
            std::cout << "  None\n";
        } else {
            for (const auto& record :
                 difference.added) {
                printRecord("  + ", record);
            }
        }

        std::cout
            << "\nNo-longer-observed open services:\n";

        if (difference.removed.empty()) {
            std::cout << "  None\n";
        } else {
            for (const auto& record :
                 difference.removed) {
                printRecord("  - ", record);
            }
        }

        std::cout
            << "\nChanged service identification:\n";

        if (difference.changed.empty()) {
            std::cout << "  None\n";
        } else {
            for (const auto& pair :
                 difference.changed) {
                std::cout
                    << "  * "
                    << pair.first.key.host
                    << ":"
                    << pair.first.key.port
                    << "/"
                    << pair.first.key.protocol
                    << " "
                    << describe(pair.first)
                    << " -> "
                    << describe(pair.second)
                    << "\n";
            }
        }
    }

private:
    static std::string describe(
        const InventoryRecord& record
    ) {
        std::ostringstream output;

        output
            << (record.service.empty()
                    ? "unknown"
                    : record.service);

        if (!record.product.empty()) {
            output
                << " "
                << record.product;
        }

        if (!record.version.empty()) {
            output
                << " "
                << record.version;
        }

        return output.str();
    }

    static void printRecord(
        const std::string& prefix,
        const InventoryRecord& record
    ) {
        std::cout
            << prefix
            << record.key.host
            << ":"
            << record.key.port
            << "/"
            << record.key.protocol
            << " "
            << describe(record)
            << "\n";
    }
};


// ---------------------------------------------------------------------------
// Defensive interpretation
// ---------------------------------------------------------------------------

class DefensiveInterpreter {
public:
    static void analyze(
        const DefensiveInventory& inventory
    ) {
        std::cout
            << "\n"
            << "DEFENSIVE INTERPRETATION\n"
            << "-----------------------\n";

        for (const auto& host :
             inventory.hosts()) {
            std::cout
                << "\n"
                << host.address
                << ":\n";

            for (const auto& port :
                 host.ports) {
                if (port.state == "open") {
                    std::cout
                        << "  OPEN "
                        << port.port
                        << "/"
                        << port.protocol
                        << " -> "
                        << (
                            port.service.empty()
                                ? "unknown service"
                                : port.service
                        )
                        << "\n";
                } else if (
                    port.state == "filtered"
                ) {
                    std::cout
                        << "  FILTERED "
                        << port.port
                        << "/"
                        << port.protocol
                        << " -> state is not fully determined\n";
                } else if (
                    port.state == "closed"
                ) {
                    std::cout
                        << "  CLOSED "
                        << port.port
                        << "/"
                        << port.protocol
                        << " -> reachable but not listening\n";
                }
            }

            std::cout
                << "  Review each open service against the approved inventory.\n";
            std::cout
                << "  Do not treat exposure alone as proof of vulnerability.\n";
        }
    }
};


// ---------------------------------------------------------------------------
// Educational sample
// ---------------------------------------------------------------------------

std::string sampleXml() {
    return R"(<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <hostnames>
      <hostname name="internal-web"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Example Web Server" version="1.2"/>
        <script id="http-title" output="Internal Application"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
      </port>
    </ports>
  </host>
</nmaprun>
)";
}


// ---------------------------------------------------------------------------
// File handling
// ---------------------------------------------------------------------------

std::string readFile(
    const std::string& filename
) {
    std::ifstream input(
        filename,
        std::ios::in | std::ios::binary
    );

    if (!input) {
        throw std::runtime_error(
            "Could not open file: " + filename
        );
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();

    return buffer.str();
}


// ---------------------------------------------------------------------------
// Timing explanation
// ---------------------------------------------------------------------------

void explainTiming() {
    std::cout
        << "\n"
        << "TIMING AND PERFORMANCE\n"
        << "----------------------\n";

    const std::map<std::string, std::string>
        timingProfiles = {
            {"-T0", "extremely conservative"},
            {"-T1", "very conservative"},
            {"-T2", "polite"},
            {"-T3", "normal/default"},
            {"-T4", "aggressive"},
            {"-T5", "very aggressive"}
        };

    for (const auto& [profile, description] :
         timingProfiles) {
        std::cout
            << "  "
            << std::setw(4)
            << std::left
            << profile
            << description
            << "\n";
    }

    std::cout
        << "\nTiming affects packet scheduling, parallelism,"
        << " retransmissions, and elapsed time.\n";

    std::cout
        << "The fastest timing template is not automatically"
        << " the most reliable operational choice.\n";
}


// ---------------------------------------------------------------------------
// Architecture explanation
// ---------------------------------------------------------------------------

void explainArchitecture() {
    std::cout
        << "\n"
        << "CASE STUDY ARCHITECTURE\n"
        << "-----------------------\n";

    std::cout
        << "1. Collection layer: Nmap produces XML snapshots.\n"
        << "2. Parsing layer: NmapXmlParser extracts structured observations.\n"
        << "3. Domain layer: HostObservation and PortObservation model inventory.\n"
        << "4. Analysis layer: DefensiveInventory normalizes open services.\n"
        << "5. Comparison layer: InventoryComparator detects service changes.\n"
        << "6. Reporting layer: DefensiveInterpreter produces cautious findings.\n";

    std::cout
        << "\nThe architecture separates collection from analysis."
        << " This makes repeated offline analysis possible without rescanning.\n";
}


// ---------------------------------------------------------------------------
// Complexity explanation
// ---------------------------------------------------------------------------

void explainComplexity() {
    std::cout
        << "\n"
        << "COMPLEXITY CONSIDERATIONS\n"
        << "-------------------------\n";

    std::cout
        << "XML extraction in this simplified parser is approximately"
        << " linear for each search operation, although repeated substring"
        << " searches can make the complete process less efficient than"
        << " a streaming XML parser on very large documents.\n";

    std::cout
        << "Inventory comparison uses std::map, providing O(log n)"
        << " insertion and lookup, with O(n log n) overall map construction"
        << " and O(n log n) ordered traversal characteristics.\n";

    std::cout
        << "For very large scan archives, a production implementation could"
        << " use a streaming parser and a database or indexed storage layer.\n";
}


// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    try {
        std::cout
            << "ADVANCED NMAP DEFENSIVE INVENTORY CASE STUDY\n";

        const auto now =
            std::chrono::system_clock::now();

        const std::time_t timestamp =
            std::chrono::system_clock::to_time_t(now);

        std::cout
            << "Timestamp: "
            << std::put_time(
                std::localtime(&timestamp),
                "%Y-%m-%d %H:%M:%S"
            )
            << "\n";

        explainArchitecture();
        explainTiming();
        explainComplexity();

        NmapXmlParser parser;

        if (argc == 1) {
            std::cout
                << "\n"
                << "No XML files supplied. Using an embedded"
                << " controlled sample for demonstration.\n";

            const auto hosts =
                parser.parse(sampleXml());

            DefensiveInventory inventory(hosts);

            inventory.printReport();
            DefensiveInterpreter::analyze(inventory);

            std::cout
                << "\n"
                << "Case-study observations:\n"
                << "  - 22/tcp is recorded as an open SSH service.\n"
                << "  - 80/tcp is recorded as an open HTTP service.\n"
                << "  - 443/tcp is recorded as filtered.\n"
                << "  - None of these states alone establishes a vulnerability.\n";

            std::cout
                << "\n"
                << "NSE evidence is stored with the port observation so"
                << " automated reporting can preserve script context.\n";

            return 0;
        }

        if (argc == 2) {
            const std::string currentXml =
                readFile(argv[1]);

            const auto hosts =
                parser.parse(currentXml);

            DefensiveInventory inventory(hosts);

            inventory.printReport();
            DefensiveInterpreter::analyze(inventory);

            return 0;
        }

        if (argc == 3) {
            const std::string baselineXml =
                readFile(argv[1]);

            const std::string currentXml =
                readFile(argv[2]);

            const auto baselineHosts =
                parser.parse(baselineXml);

            const auto currentHosts =
                parser.parse(currentXml);

            DefensiveInventory baseline(
                baselineHosts
            );

            DefensiveInventory current(
                currentHosts
            );

            std::cout
                << "\nBASELINE INVENTORY\n";

            baseline.printReport();

            std::cout
                << "\nCURRENT INVENTORY\n";

            current.printReport();

            const auto difference =
                InventoryComparator::compare(
                    baseline,
                    current
                );

            InventoryComparator::print(
                difference
            );

            DefensiveInterpreter::analyze(
                current
            );

            std::cout
                << "\n"
                << "Operational interpretation:\n"
                << "A detected change should be validated against"
                << " authorized configuration changes, deployment records,"
                << " and the approved service inventory before escalation.\n";

            return 0;
        }

        std::cerr
            << "Usage:\n"
            << "  "
            << argv[0]
            << "\n"
            << "  "
            << argv[0]
            << " current.xml\n"
            << "  "
            << argv[0]
            << " baseline.xml current.xml\n";

        return 1;
    }
    catch (const std::exception& error) {
        std::cerr
            << "ERROR: "
            << error.what()
            << "\n";

        return 1;
    }
}
