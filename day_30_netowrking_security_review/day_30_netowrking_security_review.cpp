#include <algorithm>
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

/*
 * Networking Security Review Case Study
 *
 * Scenario:
 * A company is reviewing a multi-zone enterprise network containing:
 *
 *   Internet
 *       |
 *      DMZ
 *       |
 *   Application
 *       |
 *    Database
 *
 * Employee endpoints and a dedicated management network are modeled as
 * separate trust zones.
 *
 * The program implements a merge-eligibility-style policy engine for network
 * governance: an asset/service configuration becomes acceptable only when
 * exposure, protocol security, and inter-zone flows satisfy explicit rules.
 *
 * This is a static defensive model. It does not scan networks or transmit
 * packets.
 *
 * C++17 features used:
 * - strongly typed enumerations
 * - classes and value objects
 * - vectors, maps, sets
 * - optional results
 * - exception-based validation
 * - deterministic policy evaluation
 * - complexity-aware indexed lookups
 */

enum class ProtocolSecurity {
    Secure,
    Legacy,
    Insecure,
    ContextDependent
};

enum class Severity {
    Low,
    Medium,
    High,
    Critical
};

std::string toString(ProtocolSecurity value) {
    switch (value) {
        case ProtocolSecurity::Secure:
            return "secure";
        case ProtocolSecurity::Legacy:
            return "legacy";
        case ProtocolSecurity::Insecure:
            return "insecure";
        case ProtocolSecurity::ContextDependent:
            return "context-dependent";
    }

    return "unknown";
}

std::string toString(Severity value) {
    switch (value) {
        case Severity::Low:
            return "low";
        case Severity::Medium:
            return "medium";
        case Severity::High:
            return "high";
        case Severity::Critical:
            return "critical";
    }

    return "unknown";
}

Severity severityFromScore(double score) {
    if (score >= 8.0) {
        return Severity::Critical;
    }

    if (score >= 6.0) {
        return Severity::High;
    }

    if (score >= 3.0) {
        return Severity::Medium;
    }

    return Severity::Low;
}

struct Service {
    int port;
    std::string protocol;
    std::string transport;
    std::string purpose;
    ProtocolSecurity security;
    bool authenticated;
    bool encrypted;
    bool internetExposed;

    void validate() const {
        if (port < 1 || port > 65535) {
            throw std::invalid_argument(
                "Service port must be between 1 and 65535."
            );
        }

        if (transport != "tcp" && transport != "udp") {
            throw std::invalid_argument(
                "Transport must be tcp or udp."
            );
        }

        if (protocol.empty()) {
            throw std::invalid_argument(
                "Protocol name cannot be empty."
            );
        }

        if (security == ProtocolSecurity::Secure && !encrypted) {
            throw std::invalid_argument(
                "A secure protocol classification requires encryption."
            );
        }
    }
};

struct Asset {
    std::string id;
    std::string hostname;
    std::string address;
    std::string zone;
    std::string owner;
    std::string businessRole;
    int criticality;
    std::vector<Service> services;

    void validate() const {
        if (id.empty() || hostname.empty() || address.empty()) {
            throw std::invalid_argument(
                "Asset identity fields cannot be empty."
            );
        }

        if (criticality < 1 || criticality > 5) {
            throw std::invalid_argument(
                "Asset criticality must be between 1 and 5."
            );
        }

        for (const auto& service : services) {
            service.validate();
        }
    }
};

struct Zone {
    std::string name;
    std::string cidr;
    std::string purpose;
    int trust;

    void validate() const {
        if (name.empty() || cidr.empty()) {
            throw std::invalid_argument(
                "Zone name and CIDR cannot be empty."
            );
        }

        if (trust < 1 || trust > 5) {
            throw std::invalid_argument(
                "Zone trust must be between 1 and 5."
            );
        }
    }
};

struct FlowRule {
    std::string source;
    std::string destination;
    std::string service;
    int port;
    bool allowed;
    std::string businessReason;

    void validate() const {
        if (source.empty() || destination.empty()) {
            throw std::invalid_argument(
                "Flow source and destination are required."
            );
        }

        if (port < 1 || port > 65535) {
            throw std::invalid_argument(
                "Flow port is outside the valid range."
            );
        }
    }
};

struct Finding {
    std::string category;
    Severity severity;
    std::string asset;
    std::string title;
    std::string evidence;
    std::string recommendation;
    double score;
};

class NetworkInventory {
private:
    std::vector<Asset> assets_;
    std::map<std::string, const Asset*> index_;

public:
    explicit NetworkInventory(std::vector<Asset> assets)
        : assets_(std::move(assets)) {
        rebuildIndex();
    }

    void validate() const {
        if (assets_.empty()) {
            throw std::invalid_argument(
                "Network inventory cannot be empty."
            );
        }

        std::set<std::string> addresses;

        for (const auto& asset : assets_) {
            asset.validate();

            if (!addresses.insert(asset.address).second) {
                throw std::invalid_argument(
                    "Duplicate IP address detected: " + asset.address
                );
            }
        }
    }

    void rebuildIndex() {
        index_.clear();

        for (const auto& asset : assets_) {
            const auto [it, inserted] =
                index_.emplace(asset.id, &asset);

            if (!inserted) {
                throw std::invalid_argument(
                    "Duplicate asset ID: " + asset.id
                );
            }
        }
    }

    const std::vector<Asset>& assets() const {
        return assets_;
    }

    const Asset* find(const std::string& id) const {
        const auto it = index_.find(id);

        if (it == index_.end()) {
            return nullptr;
        }

        return it->second;
    }

    std::size_t serviceCount() const {
        std::size_t total = 0;

        for (const auto& asset : assets_) {
            total += asset.services.size();
        }

        return total;
    }
};

class ExposureReview {
public:
    std::vector<Finding> evaluate(
        const NetworkInventory& inventory
    ) const {
        std::vector<Finding> findings;

        inventory.validate();

        for (const auto& asset : inventory.assets()) {
            std::size_t publicCount = 0;

            for (const auto& service : asset.services) {
                if (!service.internetExposed) {
                    continue;
                }

                ++publicCount;

                if (
                    service.security == ProtocolSecurity::Insecure ||
                    service.security == ProtocolSecurity::Legacy
                ) {
                    double score =
                        service.security == ProtocolSecurity::Insecure
                            ? 8.0
                            : 6.5;

                    if (!service.authenticated) {
                        score += 1.0;
                    }

                    score = std::min(score, 10.0);

                    Finding finding{
                        "insecure_protocol",
                        severityFromScore(score),
                        asset.id,
                        "Risky Internet-facing protocol",
                        service.protocol + "/" +
                            service.transport + ":" +
                            std::to_string(service.port) +
                            " is Internet exposed; encrypted=" +
                            (service.encrypted ? "true" : "false") +
                            ", authenticated=" +
                            (service.authenticated ? "true" : "false"),
                        "Replace the protocol with an authenticated and " +
                            "encrypted alternative or remove public exposure.",
                        score
                    };

                    findings.push_back(std::move(finding));
                }

                if (!service.authenticated) {
                    double score =
                        std::min(
                            10.0,
                            5.0 + asset.criticality * 0.7
                        );

                    findings.push_back(Finding{
                        "exposed_service",
                        severityFromScore(score),
                        asset.id,
                        "Public service lacks authentication",
                        service.protocol + ":" +
                            std::to_string(service.port) +
                            " has no modeled authentication control.",
                        "Restrict access or add a strong authentication " +
                            "mechanism appropriate to the service.",
                        score
                    });
                }
            }

            /*
             * Four or more public endpoints are not automatically vulnerable.
             * The finding signals an unusually large attack surface that
             * deserves explicit business justification and lifecycle review.
             */
            if (publicCount >= 4) {
                findings.push_back(Finding{
                    "attack_surface",
                    Severity::High,
                    asset.id,
                    "Large public endpoint surface",
                    std::to_string(publicCount) +
                        " Internet-facing services are assigned to this asset.",
                    "Remove unnecessary endpoints and isolate administrative " +
                        "interfaces from the public boundary.",
                    7.0
                });
            }

            /*
             * A high-criticality service in a user zone increases the impact
             * of compromise of ordinary endpoints because the trust boundary
             * between users and the service is weaker than a dedicated
             * application or database segment.
             */
            if (
                asset.zone == "user" &&
                asset.criticality >= 4
            ) {
                findings.push_back(Finding{
                    "segmentation",
                    Severity::High,
                    asset.id,
                    "High-criticality service resides in user zone",
                    "criticality=" +
                        std::to_string(asset.criticality) +
                        ", zone=user",
                    "Evaluate moving the service into a dedicated " +
                        "application or protected server segment.",
                    6.0
                });
            }
        }

        return findings;
    }
};

class SegmentationPolicyEngine {
private:
    std::map<std::string, Zone> zones_;
    std::vector<FlowRule> rules_;

    bool hasAllowedFlow(
        const std::string& source,
        const std::string& destination
    ) const {
        return std::any_of(
            rules_.begin(),
            rules_.end(),
            [&](const FlowRule& rule) {
                return rule.allowed &&
                    rule.source == source &&
                    rule.destination == destination;
            }
        );
    }

public:
    SegmentationPolicyEngine(
        std::vector<Zone> zones,
        std::vector<FlowRule> rules
    )
        : rules_(std::move(rules)) {
        for (const auto& zone : zones) {
            zone.validate();

            const auto [it, inserted] =
                zones_.emplace(zone.name, zone);

            if (!inserted) {
                throw std::invalid_argument(
                    "Duplicate zone name: " + zone.name
                );
            }
        }

        for (const auto& rule : rules_) {
            rule.validate();

            if (!zones_.contains(rule.source)) {
                throw std::invalid_argument(
                    "Unknown source zone: " + rule.source
                );
            }

            if (!zones_.contains(rule.destination)) {
                throw std::invalid_argument(
                    "Unknown destination zone: " +
                    rule.destination
                );
            }
        }
    }

    std::vector<Finding> evaluate() const {
        std::vector<Finding> findings;

        /*
         * Protected zones are not protected merely because they have a
         * different subnet. The engine expects explicit inter-zone policy.
         */
        for (const auto& [sourceName, sourceZone] : zones_) {
            for (const auto& [destinationName, destinationZone] : zones_) {
                if (sourceName == destinationName) {
                    continue;
                }

                if (destinationZone.trust < 4) {
                    continue;
                }

                if (!hasAllowedFlow(sourceName, destinationName)) {
                    findings.push_back(Finding{
                        "segmentation",
                        Severity::High,
                        destinationName,
                        "No explicit inbound flow to protected zone",
                        sourceName +
                            " has no approved flow into " +
                            destinationName,
                        "Document required application traffic and " +
                            "allow only the required service flows.",
                        6.5
                    });
                }
            }
        }

        /*
         * SSH and RDP are administrative protocols. A rule permitting them
         * from an ordinary user network into a highly trusted zone represents
         * a different governance issue from merely exposing HTTPS.
         */
        for (const auto& rule : rules_) {
            if (!rule.allowed) {
                continue;
            }

            const auto destinationIt =
                zones_.find(rule.destination);

            if (destinationIt == zones_.end()) {
                continue;
            }

            if (
                destinationIt->second.trust >= 4 &&
                (rule.port == 22 || rule.port == 3389)
            ) {
                findings.push_back(Finding{
                    "segmentation",
                    Severity::High,
                    rule.destination,
                    "Administrative access crosses protected boundary",
                    rule.source + " -> " +
                        rule.destination + " permits " +
                        rule.service + ":" +
                        std::to_string(rule.port),
                    "Move administrative access to a dedicated management " +
                        "path or tightly controlled administrative hosts.",
                    7.0
                });
            }
        }

        return findings;
    }
};

struct ReviewResult {
    std::vector<Finding> findings;
    std::size_t assets;
    std::size_t services;
};

class SecurityReviewEngine {
private:
    NetworkInventory inventory_;
    ExposureReview exposureReview_;
    SegmentationPolicyEngine segmentation_;

public:
    SecurityReviewEngine(
        NetworkInventory inventory,
        SegmentationPolicyEngine segmentation
    )
        : inventory_(std::move(inventory)),
          segmentation_(std::move(segmentation)) {}

    ReviewResult run() const {
        std::vector<Finding> findings =
            exposureReview_.evaluate(inventory_);

        std::vector<Finding> segmentationFindings =
            segmentation_.evaluate();

        findings.insert(
            findings.end(),
            segmentationFindings.begin(),
            segmentationFindings.end()
        );

        std::sort(
            findings.begin(),
            findings.end(),
            [](const Finding& left, const Finding& right) {
                if (left.score != right.score) {
                    return left.score > right.score;
                }

                if (left.asset != right.asset) {
                    return left.asset < right.asset;
                }

                return left.title < right.title;
            }
        );

        return ReviewResult{
            std::move(findings),
            inventory_.assets().size(),
            inventory_.serviceCount()
        };
    }
};

void printInventory(const NetworkInventory& inventory) {
    std::cout << "\n=== NETWORK INVENTORY ===\n";

    for (const auto& asset : inventory.assets()) {
        std::cout
            << "\n"
            << asset.id
            << " | "
            << asset.hostname
            << " | zone="
            << asset.zone
            << " | criticality="
            << asset.criticality
            << "\n";

        for (const auto& service : asset.services) {
            std::cout
                << "  "
                << service.protocol
                << "/"
                << service.port
                << " "
                << service.transport
                << " | exposed="
                << (service.internetExposed ? "yes" : "no")
                << " | encrypted="
                << (service.encrypted ? "yes" : "no")
                << " | authenticated="
                << (service.authenticated ? "yes" : "no")
                << "\n";
        }
    }
}

void printFindings(const std::vector<Finding>& findings) {
    std::cout << "\n=== SECURITY FINDINGS ===\n";

    if (findings.empty()) {
        std::cout << "No findings.\n";
        return;
    }

    for (const auto& finding : findings) {
        std::cout
            << "\n["
            << toString(finding.severity)
            << "] "
            << finding.category
            << " | "
            << finding.asset
            << "\n";

        std::cout
            << "Title: "
            << finding.title
            << "\n";

        std::cout
            << "Evidence: "
            << finding.evidence
            << "\n";

        std::cout
            << "Recommendation: "
            << finding.recommendation
            << "\n";

        std::cout
            << "Risk score: "
            << std::fixed
            << std::setprecision(1)
            << finding.score
            << "\n";
    }
}

void writeReport(
    const ReviewResult& result,
    const std::string& filename
) {
    std::ofstream output(filename);

    if (!output) {
        throw std::runtime_error(
            "Unable to create report: " + filename
        );
    }

    /*
     * JSON is written manually to keep the program dependency-free.
     * The escape helper prevents quotation marks in evidence text from
     * producing invalid JSON.
     */
    auto escapeJson = [](const std::string& input) {
        std::string escaped;

        for (char character : input) {
            switch (character) {
                case '"':
                    escaped += "\\\"";
                    break;
                case '\\':
                    escaped += "\\\\";
                    break;
                case '\n':
                    escaped += "\\n";
                    break;
                case '\r':
                    escaped += "\\r";
                    break;
                case '\t':
                    escaped += "\\t";
                    break;
                default:
                    escaped += character;
            }
        }

        return escaped;
    };

    output << "{\n";
    output << "  \"reviewed_assets\": "
           << result.assets
           << ",\n";
    output << "  \"reviewed_services\": "
           << result.services
           << ",\n";
    output << "  \"finding_count\": "
           << result.findings.size()
           << ",\n";
    output << "  \"findings\": [\n";

    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const auto& finding = result.findings[i];

        output << "    {\n";
        output << "      \"category\": \""
               << escapeJson(finding.category)
               << "\",\n";
        output << "      \"severity\": \""
               << escapeJson(toString(finding.severity))
               << "\",\n";
        output << "      \"asset\": \""
               << escapeJson(finding.asset)
               << "\",\n";
        output << "      \"title\": \""
               << escapeJson(finding.title)
               << "\",\n";
        output << "      \"evidence\": \""
               << escapeJson(finding.evidence)
               << "\",\n";
        output << "      \"recommendation\": \""
               << escapeJson(finding.recommendation)
               << "\",\n";
        output << "      \"score\": "
               << std::fixed
               << std::setprecision(1)
               << finding.score
               << "\n";
        output << "    }";

        if (i + 1 < result.findings.size()) {
            output << ",";
        }

        output << "\n";
    }

    output << "  ]\n";
    output << "}\n";
}

std::vector<Asset> createAssets() {
    return {
        Asset{
            "web-gateway",
            "web-gateway.example.internal",
            "10.40.10.20",
            "dmz",
            "Web Platform",
            "Public application gateway",
            4,
            {
                Service{
                    443,
                    "HTTPS",
                    "tcp",
                    "Public web application",
                    ProtocolSecurity::Secure,
                    true,
                    true,
                    true
                },
                Service{
                    22,
                    "SSH",
                    "tcp",
                    "Administration",
                    ProtocolSecurity::Secure,
                    true,
                    true,
                    true
                }
            }
        },
        Asset{
            "legacy-transfer",
            "legacy-transfer.example.internal",
            "10.40.20.20",
            "user",
            "Operations",
            "Legacy file transfer",
            4,
            {
                Service{
                    21,
                    "FTP",
                    "tcp",
                    "Legacy file transfer",
                    ProtocolSecurity::Insecure,
                    false,
                    false,
                    true
                }
            }
        },
        Asset{
            "application-api",
            "application-api.example.internal",
            "10.40.30.20",
            "application",
            "Application Team",
            "Internal API",
            5,
            {
                Service{
                    443,
                    "HTTPS",
                    "tcp",
                    "Application API",
                    ProtocolSecurity::Secure,
                    true,
                    true,
                    false
                }
            }
        },
        Asset{
            "transaction-db",
            "transaction-db.example.internal",
            "10.40.40.20",
            "database",
            "Data Platform",
            "Transactional database",
            5,
            {
                Service{
                    5432,
                    "PostgreSQL",
                    "tcp",
                    "Application database",
                    ProtocolSecurity::Secure,
                    true,
                    true,
                    false
                }
            }
        }
    };
}

std::vector<Zone> createZones() {
    return {
        Zone{
            "internet",
            "0.0.0.0/0",
            "Untrusted external network",
            1
        },
        Zone{
            "user",
            "10.40.20.0/24",
            "Employee endpoint network",
            2
        },
        Zone{
            "dmz",
            "10.40.10.0/24",
            "Public application boundary",
            3
        },
        Zone{
            "application",
            "10.40.30.0/24",
            "Application services",
            4
        },
        Zone{
            "database",
            "10.40.40.0/24",
            "Transactional data services",
            5
        },
        Zone{
            "management",
            "10.40.50.0/24",
            "Administrative network",
            5
        }
    };
}

std::vector<FlowRule> createRules() {
    return {
        FlowRule{
            "internet",
            "dmz",
            "HTTPS",
            443,
            true,
            "Public web traffic"
        },
        FlowRule{
            "dmz",
            "application",
            "HTTPS",
            443,
            true,
            "Reverse proxy to application tier"
        },
        FlowRule{
            "application",
            "database",
            "PostgreSQL",
            5432,
            true,
            "Application database access"
        },
        FlowRule{
            "user",
            "management",
            "SSH",
            22,
            true,
            "Broad employee administration path"
        }
    };
}

int main() {
    try {
        std::cout
            << "NETWORKING SECURITY REVIEW\n"
            << "==========================\n";

        NetworkInventory inventory(createAssets());

        SegmentationPolicyEngine segmentation(
            createZones(),
            createRules()
        );

        SecurityReviewEngine engine(
            std::move(inventory),
            std::move(segmentation)
        );

        const ReviewResult result = engine.run();

        /*
         * The inventory is recreated for presentation because the review
         * engine owns its inventory. This keeps ownership explicit and
         * avoids global state.
         */
        NetworkInventory presentationInventory(createAssets());

        printInventory(presentationInventory);
        printFindings(result.findings);

        writeReport(
            result,
            "network_security_review_cpp.json"
        );

        std::cout
            << "\nReviewed assets: "
            << result.assets
            << "\nReviewed services: "
            << result.services
            << "\nReport: network_security_review_cpp.json\n";

        return 0;
    }
    catch (const std::invalid_argument& error) {
        std::cerr
            << "Configuration validation failed: "
            << error.what()
            << "\n";
        return 2;
    }
    catch (const std::runtime_error& error) {
        std::cerr
            << "Runtime failure: "
            << error.what()
            << "\n";
        return 3;
    }
    catch (const std::exception& error) {
        std::cerr
            << "Unexpected failure: "
            << error.what()
            << "\n";
        return 4;
    }
}
