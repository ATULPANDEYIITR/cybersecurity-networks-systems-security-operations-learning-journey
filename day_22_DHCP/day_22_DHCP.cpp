/*
 * DHCP Learning Lab
 *
 * Modern C++17 case study:
 *
 * A small enterprise network is modeled with:
 *   - DHCP clients
 *   - An authorized DHCP server
 *   - An unauthorized/rogue DHCP server
 *   - DHCPDISCOVER/DHCPOFFER/DHCPREQUEST/DHCPACK
 *   - Lease allocation and expiration
 *   - DHCP pool exhaustion
 *   - DHCP server validation
 *   - Rogue DHCP detection
 *   - Wireshark-oriented packet analysis
 *
 * This is a simulation. It does not transmit packets onto a real network
 * and does not modify the host operating system's network configuration.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -Wextra -pedantic dhcp_learning.cpp -o dhcp_learning
 *
 * Run:
 *   ./dhcp_learning
 */

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;


// ============================================================================
// 1. DHCP protocol vocabulary
// ============================================================================

enum class DHCPMessageType {
    Discover,
    Offer,
    Request,
    Ack,
    Nak,
    Decline,
    Release,
    Inform
};

string messageTypeToString(DHCPMessageType type) {
    switch (type) {
        case DHCPMessageType::Discover: return "DHCPDISCOVER";
        case DHCPMessageType::Offer:    return "DHCPOFFER";
        case DHCPMessageType::Request:  return "DHCPREQUEST";
        case DHCPMessageType::Ack:      return "DHCPACK";
        case DHCPMessageType::Nak:      return "DHCPNAK";
        case DHCPMessageType::Decline:  return "DHCPDECLINE";
        case DHCPMessageType::Release:  return "DHCPRELEASE";
        case DHCPMessageType::Inform:   return "DHCPINFORM";
    }

    return "UNKNOWN";
}

enum class ClientState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Expired
};

string clientStateToString(ClientState state) {
    switch (state) {
        case ClientState::Init:       return "INIT";
        case ClientState::Selecting:  return "SELECTING";
        case ClientState::Requesting: return "REQUESTING";
        case ClientState::Bound:      return "BOUND";
        case ClientState::Renewing:   return "RENEWING";
        case ClientState::Rebinding:  return "REBINDING";
        case ClientState::Expired:    return "EXPIRED";
    }

    return "UNKNOWN";
}


// ============================================================================
// 2. DHCP packet representation
// ============================================================================

struct DHCPPacket {
    DHCPMessageType messageType;

    uint32_t transactionId;

    string clientMac;

    string sourceIp = "0.0.0.0";
    string destinationIp = "255.255.255.255";

    optional<string> serverIdentifier;
    optional<string> requestedIp;
    optional<string> offeredIp;

    optional<string> subnetMask;
    optional<string> router;

    vector<string> dnsServers;

    optional<int> leaseSeconds;

    string summary() const {
        ostringstream output;

        output
            << left
            << setw(14)
            << messageTypeToString(messageType)
            << " xid=0x"
            << hex
            << setw(8)
            << setfill('0')
            << transactionId
            << dec
            << setfill(' ')
            << " client="
            << clientMac
            << " src="
            << sourceIp
            << " dst="
            << destinationIp;

        return output.str();
    }
};


// ============================================================================
// 3. Lease representation
// ============================================================================

struct DHCPLease {
    string macAddress;
    string ipAddress;
    string serverIdentifier;

    int leaseSeconds;

    long long startTimeSeconds;

    bool released = false;

    long long expirationTime() const {
        return startTimeSeconds + leaseSeconds;
    }

    bool expired(long long currentTime) const {
        return released || currentTime >= expirationTime();
    }

    int remainingSeconds(long long currentTime) const {
        if (expired(currentTime)) {
            return 0;
        }

        return static_cast<int>(
            expirationTime() - currentTime
        );
    }
};


// ============================================================================
// 4. Simulation clock
// ============================================================================

class SimulationClock {
private:
    long long currentTime_;

public:
    explicit SimulationClock(long long initialTime = 100000)
        : currentTime_(initialTime) {}

    long long now() const {
        return currentTime_;
    }

    void advance(long long seconds) {
        if (seconds < 0) {
            throw invalid_argument(
                "Simulation time cannot move backward."
            );
        }

        currentTime_ += seconds;
    }
};


// ============================================================================
// 5. DHCP server
// ============================================================================

class DHCPServer {
private:
    string serverIdentifier_;

    vector<string> addressPool_;

    string subnetMask_;
    string router_;

    vector<string> dnsServers_;

    int leaseSeconds_;

    SimulationClock& clock_;

    /*
     * Two indexes are maintained:
     *
     * MAC -> lease
     * IP  -> lease
     *
     * This avoids repeatedly scanning every lease for common lookups.
     */
    unordered_map<string, DHCPLease> leasesByMac_;
    unordered_map<string, string> macByIp_;

    void removeExpiredLeases() {
        vector<string> expiredMacs;

        for (const auto& [mac, lease] : leasesByMac_) {
            if (lease.expired(clock_.now())) {
                expiredMacs.push_back(mac);
            }
        }

        for (const string& mac : expiredMacs) {
            auto iterator = leasesByMac_.find(mac);

            if (iterator != leasesByMac_.end()) {
                macByIp_.erase(iterator->second.ipAddress);
                leasesByMac_.erase(iterator);
            }
        }
    }

    optional<string> findAvailableAddress() {
        removeExpiredLeases();

        for (const string& address : addressPool_) {
            if (!macByIp_.contains(address)) {
                return address;
            }
        }

        return nullopt;
    }

    DHCPPacket createNak(const DHCPPacket& request) const {
        DHCPPacket response;

        response.messageType = DHCPMessageType::Nak;
        response.transactionId = request.transactionId;
        response.clientMac = request.clientMac;
        response.sourceIp = serverIdentifier_;
        response.destinationIp = "255.255.255.255";
        response.serverIdentifier = serverIdentifier_;

        return response;
    }

public:
    DHCPServer(
        string serverIdentifier,
        vector<string> addressPool,
        string subnetMask,
        string router,
        vector<string> dnsServers,
        int leaseSeconds,
        SimulationClock& clock
    )
        : serverIdentifier_(move(serverIdentifier)),
          addressPool_(move(addressPool)),
          subnetMask_(move(subnetMask)),
          router_(move(router)),
          dnsServers_(move(dnsServers)),
          leaseSeconds_(leaseSeconds),
          clock_(clock) {

        if (addressPool_.empty()) {
            throw invalid_argument(
                "DHCP address pool cannot be empty."
            );
        }

        if (leaseSeconds_ <= 0) {
            throw invalid_argument(
                "Lease duration must be positive."
            );
        }
    }

    const string& identifier() const {
        return serverIdentifier_;
    }

    DHCPPacket receiveDiscover(const DHCPPacket& discover) {
        if (discover.messageType != DHCPMessageType::Discover) {
            throw invalid_argument(
                "DHCP server expected DHCPDISCOVER."
            );
        }

        auto existing = leasesByMac_.find(
            discover.clientMac
        );

        optional<string> offeredIp;

        if (
            existing != leasesByMac_.end() &&
            !existing->second.expired(clock_.now())
        ) {
            offeredIp = existing->second.ipAddress;
        } else {
            offeredIp = findAvailableAddress();
        }

        if (!offeredIp.has_value()) {
            throw runtime_error(
                "DHCP address pool exhausted."
            );
        }

        DHCPPacket offer;

        offer.messageType = DHCPMessageType::Offer;
        offer.transactionId = discover.transactionId;
        offer.clientMac = discover.clientMac;
        offer.sourceIp = serverIdentifier_;
        offer.destinationIp = "255.255.255.255";

        offer.serverIdentifier = serverIdentifier_;
        offer.offeredIp = offeredIp;
        offer.subnetMask = subnetMask_;
        offer.router = router_;
        offer.dnsServers = dnsServers_;
        offer.leaseSeconds = leaseSeconds_;

        return offer;
    }

    DHCPPacket receiveRequest(const DHCPPacket& request) {
        if (request.messageType != DHCPMessageType::Request) {
            throw invalid_argument(
                "DHCP server expected DHCPREQUEST."
            );
        }

        /*
         * Option 54 identifies the selected DHCP server.
         * If another server was selected, this server should not commit
         * the lease for this transaction.
         */
        if (
            !request.serverIdentifier.has_value() ||
            request.serverIdentifier.value() != serverIdentifier_
        ) {
            return createNak(request);
        }

        if (!request.requestedIp.has_value()) {
            return createNak(request);
        }

        const string requestedIp = request.requestedIp.value();

        /*
         * The simulation's pool itself defines which addresses can be
         * allocated. A real server would also consider subnet, reservations,
         * exclusions, conflicts, and persistent lease state.
         */
        if (
            find(addressPool_.begin(), addressPool_.end(), requestedIp)
            == addressPool_.end()
        ) {
            return createNak(request);
        }

        auto ipOwner = macByIp_.find(requestedIp);

        if (
            ipOwner != macByIp_.end() &&
            ipOwner->second != request.clientMac
        ) {
            auto otherLease = leasesByMac_.find(ipOwner->second);

            if (
                otherLease != leasesByMac_.end() &&
                !otherLease->second.expired(clock_.now())
            ) {
                return createNak(request);
            }

            macByIp_.erase(ipOwner);
        }

        /*
         * If the client already owns another address, remove that mapping.
         * This models a client changing its active allocation.
         */
        auto previous = leasesByMac_.find(
            request.clientMac
        );

        if (
            previous != leasesByMac_.end() &&
            previous->second.ipAddress != requestedIp
        ) {
            macByIp_.erase(previous->second.ipAddress);
        }

        DHCPLease lease{
            request.clientMac,
            requestedIp,
            serverIdentifier_,
            leaseSeconds_,
            clock_.now(),
            false
        };

        leasesByMac_[request.clientMac] = lease;
        macByIp_[requestedIp] = request.clientMac;

        DHCPPacket ack;

        ack.messageType = DHCPMessageType::Ack;
        ack.transactionId = request.transactionId;
        ack.clientMac = request.clientMac;
        ack.sourceIp = serverIdentifier_;
        ack.destinationIp = "255.255.255.255";

        ack.serverIdentifier = serverIdentifier_;
        ack.offeredIp = requestedIp;
        ack.subnetMask = subnetMask_;
        ack.router = router_;
        ack.dnsServers = dnsServers_;
        ack.leaseSeconds = leaseSeconds_;

        return ack;
    }

    bool releaseLease(const string& macAddress) {
        auto iterator = leasesByMac_.find(macAddress);

        if (iterator == leasesByMac_.end()) {
            return false;
        }

        macByIp_.erase(iterator->second.ipAddress);
        iterator->second.released = true;
        leasesByMac_.erase(iterator);

        return true;
    }

    void printLeaseTable() {
        removeExpiredLeases();

        cout << "\nLease table for DHCP server "
             << serverIdentifier_
             << "\n"
             << string(78, '-')
             << "\n";

        if (leasesByMac_.empty()) {
            cout << "No active leases.\n";
            return;
        }

        for (const auto& [mac, lease] : leasesByMac_) {
            cout
                << left
                << setw(22) << mac
                << setw(18) << lease.ipAddress
                << setw(14)
                << lease.remainingSeconds(clock_.now())
                << " seconds\n";
        }
    }
};


// ============================================================================
// 6. DHCP client
// ============================================================================

class DHCPClient {
private:
    string macAddress_;

    ClientState state_ = ClientState::Init;

    uint32_t transactionId_ = 0;

    optional<string> ipAddress_;
    optional<string> serverIdentifier_;

    optional<string> subnetMask_;
    optional<string> router_;

    vector<string> dnsServers_;

    optional<int> leaseSeconds_;
    optional<long long> leaseStart_;

    uint32_t generateTransactionId() const {
        /*
         * A deterministic transaction ID is useful in an educational
         * simulation. Production DHCP clients generate transaction IDs
         * using a suitable randomness source.
         */
        static uint32_t nextId = 0x10000001;
        return nextId++;
    }

public:
    explicit DHCPClient(string macAddress)
        : macAddress_(move(macAddress)) {}

    const string& macAddress() const {
        return macAddress_;
    }

    ClientState state() const {
        return state_;
    }

    DHCPPacket createDiscover() {
        transactionId_ = generateTransactionId();
        state_ = ClientState::Selecting;

        DHCPPacket discover;

        discover.messageType = DHCPMessageType::Discover;
        discover.transactionId = transactionId_;
        discover.clientMac = macAddress_;
        discover.sourceIp = "0.0.0.0";
        discover.destinationIp = "255.255.255.255";

        return discover;
    }

    DHCPPacket createRequest(const DHCPPacket& offer) {
        if (
            offer.messageType != DHCPMessageType::Offer
        ) {
            throw invalid_argument(
                "Client can request only a DHCPOFFER."
            );
        }

        if (
            offer.transactionId != transactionId_
        ) {
            throw invalid_argument(
                "Offer transaction ID does not match."
            );
        }

        if (
            !offer.offeredIp.has_value() ||
            !offer.serverIdentifier.has_value()
        ) {
            throw invalid_argument(
                "Offer lacks required address/server information."
            );
        }

        state_ = ClientState::Requesting;

        DHCPPacket request;

        request.messageType = DHCPMessageType::Request;
        request.transactionId = transactionId_;
        request.clientMac = macAddress_;
        request.sourceIp = "0.0.0.0";
        request.destinationIp = "255.255.255.255";

        request.serverIdentifier =
            offer.serverIdentifier;

        request.requestedIp =
            offer.offeredIp;

        return request;
    }

    void processResponse(
        const DHCPPacket& response,
        const SimulationClock& clock
    ) {
        if (
            response.transactionId != transactionId_
        ) {
            throw runtime_error(
                "DHCP response transaction ID mismatch."
            );
        }

        if (
            response.messageType == DHCPMessageType::Nak
        ) {
            state_ = ClientState::Init;
            ipAddress_.reset();
            serverIdentifier_.reset();
            leaseSeconds_.reset();
            leaseStart_.reset();
            return;
        }

        if (
            response.messageType != DHCPMessageType::Ack
        ) {
            throw runtime_error(
                "Expected DHCPACK or DHCPNAK."
            );
        }

        if (
            !response.offeredIp.has_value() ||
            !response.serverIdentifier.has_value() ||
            !response.leaseSeconds.has_value()
        ) {
            throw runtime_error(
                "DHCPACK lacks required lease information."
            );
        }

        ipAddress_ = response.offeredIp;
        serverIdentifier_ =
            response.serverIdentifier;

        subnetMask_ = response.subnetMask;
        router_ = response.router;
        dnsServers_ = response.dnsServers;

        leaseSeconds_ = response.leaseSeconds;
        leaseStart_ = clock.now();

        state_ = ClientState::Bound;
    }

    void updateLeaseState(
        const SimulationClock& clock
    ) {
        if (
            !leaseStart_.has_value() ||
            !leaseSeconds_.has_value()
        ) {
            return;
        }

        const long long elapsed =
            clock.now() - leaseStart_.value();

        const double fraction =
            static_cast<double>(elapsed) /
            leaseSeconds_.value();

        if (fraction >= 1.0) {
            state_ = ClientState::Expired;
        } else if (fraction >= 0.875) {
            state_ = ClientState::Rebinding;
        } else if (fraction >= 0.5) {
            state_ = ClientState::Renewing;
        } else {
            state_ = ClientState::Bound;
        }
    }

    void printConfiguration() const {
        cout << "\nClient configuration\n"
             << string(55, '-')
             << "\n";

        cout << "MAC:       " << macAddress_ << "\n";
        cout << "State:     "
             << clientStateToString(state_)
             << "\n";

        cout << "IPv4:      "
             << (ipAddress_.value_or("none"))
             << "\n";

        cout << "Subnet:    "
             << (subnetMask_.value_or("none"))
             << "\n";

        cout << "Gateway:   "
             << (router_.value_or("none"))
             << "\n";

        cout << "DHCP:      "
             << (serverIdentifier_.value_or("none"))
             << "\n";

        cout << "DNS:       ";

        if (dnsServers_.empty()) {
            cout << "none";
        } else {
            for (size_t index = 0;
                 index < dnsServers_.size();
                 ++index) {
                if (index != 0) {
                    cout << ", ";
                }

                cout << dnsServers_[index];
            }
        }

        cout << "\n";

        cout << "Lease:     ";

        if (leaseSeconds_.has_value()) {
            cout << leaseSeconds_.value()
                 << " seconds";
        } else {
            cout << "none";
        }

        cout << "\n";
    }
};


// ============================================================================
// 7. Network simulation
// ============================================================================

struct OfferObservation {
    string serverIdentifier;
    string offeredIp;
    string gateway;
    vector<string> dnsServers;
};

class NetworkSimulator {
public:
    static vector<DHCPPacket> collectOffers(
        const vector<DHCPServer*>& servers,
        const DHCPPacket& discover
    ) {
        vector<DHCPPacket> offers;

        /*
         * A DHCPDISCOVER is conceptually broadcast. Multiple DHCP servers
         * can see it and generate independent offers.
         */
        for (DHCPServer* server : servers) {
            try {
                DHCPPacket offer =
                    server->receiveDiscover(discover);

                offers.push_back(offer);
            } catch (const exception& error) {
                cerr
                    << "Server "
                    << server->identifier()
                    << " failed to process Discover: "
                    << error.what()
                    << "\n";
            }
        }

        return offers;
    }

    static vector<OfferObservation> analyzeOffers(
        const vector<DHCPPacket>& offers,
        const set<string>& trustedServerIds
    ) {
        vector<OfferObservation> findings;

        for (const DHCPPacket& offer : offers) {
            if (
                !offer.serverIdentifier.has_value() ||
                !offer.offeredIp.has_value()
            ) {
                continue;
            }

            if (
                !trustedServerIds.contains(
                    offer.serverIdentifier.value()
                )
            ) {
                findings.push_back({
                    offer.serverIdentifier.value(),
                    offer.offeredIp.value(),
                    offer.router.value_or("unknown"),
                    offer.dnsServers
                });
            }
        }

        return findings;
    }
};


// ============================================================================
// 8. Wireshark-oriented analysis
// ============================================================================

void printWiresharkFilters() {
    cout << "\n"
         << string(80, '=')
         << "\nWIRESHARK DISPLAY FILTER REFERENCE\n"
         << string(80, '=')
         << "\n";

    const vector<pair<string, string>> filters = {
        {"All DHCP", "dhcp"},
        {"All BOOTP/DHCP", "bootp"},
        {"DHCP UDP ports", "udp.port == 67 || udp.port == 68"},
        {"DHCP Discover", "bootp.option.dhcp == 1"},
        {"DHCP Offer", "bootp.option.dhcp == 2"},
        {"DHCP Request", "bootp.option.dhcp == 3"},
        {"DHCP ACK", "bootp.option.dhcp == 5"},
        {"DHCP NAK", "bootp.option.dhcp == 6"},
        {"DHCP server identifier", "bootp.option.dhcp_server"},
        {"Example client MAC",
         "eth.addr == aa:bb:cc:dd:ee:01"}
    };

    for (const auto& [name, filter] : filters) {
        cout
            << left
            << setw(28)
            << name
            << filter
            << "\n";
    }

    cout << "\nRecommended packet-analysis sequence:\n"
         << "1. Find DHCPDISCOVER.\n"
         << "2. Record transaction ID.\n"
         << "3. Identify all DHCPOFFER messages.\n"
         << "4. Compare server identifiers.\n"
         << "5. Inspect offered IP, gateway, DNS and lease time.\n"
         << "6. Locate DHCPREQUEST for the selected server.\n"
         << "7. Confirm DHCPACK or DHCPNAK.\n"
         << "8. Investigate unexpected DHCP servers.\n";
}

void printPacketAnalysis(const DHCPPacket& packet) {
    cout << "\nPacket analysis\n"
         << string(60, '-')
         << "\n";

    cout << "Message:       "
         << messageTypeToString(packet.messageType)
         << "\n";

    cout << "Transaction:   0x"
         << hex
         << setw(8)
         << setfill('0')
         << packet.transactionId
         << dec
         << setfill(' ')
         << "\n";

    cout << "Client MAC:    "
         << packet.clientMac
         << "\n";

    cout << "Source IP:     "
         << packet.sourceIp
         << "\n";

    cout << "Destination IP:"
         << packet.destinationIp
         << "\n";

    if (packet.serverIdentifier) {
        cout << "Option 54:     "
             << packet.serverIdentifier.value()
             << "\n";
    }

    if (packet.requestedIp) {
        cout << "Option 50:     "
             << packet.requestedIp.value()
             << "\n";
    }

    if (packet.offeredIp) {
        cout << "Assigned/Offer:"
             << packet.offeredIp.value()
             << "\n";
    }

    if (packet.leaseSeconds) {
        cout << "Option 51:     "
             << packet.leaseSeconds.value()
             << " seconds\n";
    }

    cout << "Option 1:      "
         << packet.subnetMask.value_or("not present")
         << "\n";

    cout << "Option 3:      "
         << packet.router.value_or("not present")
         << "\n";

    cout << "Option 6:      ";

    if (packet.dnsServers.empty()) {
        cout << "not present";
    } else {
        for (size_t index = 0;
             index < packet.dnsServers.size();
             ++index) {
            if (index != 0) {
                cout << ", ";
            }

            cout << packet.dnsServers[index];
        }
    }

    cout << "\n";
}


// ============================================================================
// 9. DORA case study
// ============================================================================

void demonstrateDora(
    DHCPServer& server,
    DHCPClient& client,
    SimulationClock& clock
) {
    cout << "\n"
         << string(80, '=')
         << "\nDORA CASE STUDY\n"
         << string(80, '=')
         << "\n";

    DHCPPacket discover =
        client.createDiscover();

    cout << "\n1. Client -> Network\n"
         << discover.summary()
         << "\n";

    DHCPPacket offer =
        server.receiveDiscover(discover);

    cout << "\n2. Server -> Client\n"
         << offer.summary()
         << "\n";

    cout << "   Offered IP: "
         << offer.offeredIp.value()
         << "\n";

    cout << "   Server ID:  "
         << offer.serverIdentifier.value()
         << "\n";

    DHCPPacket request =
        client.createRequest(offer);

    cout << "\n3. Client -> Network\n"
         << request.summary()
         << "\n";

    cout << "   Requested IP: "
         << request.requestedIp.value()
         << "\n";

    DHCPPacket ack =
        server.receiveRequest(request);

    cout << "\n4. Server -> Client\n"
         << ack.summary()
         << "\n";

    if (
        ack.messageType ==
        DHCPMessageType::Ack
    ) {
        client.processResponse(ack, clock);
        cout << "   Lease accepted.\n";
    } else {
        cout << "   Lease rejected.\n";
    }

    client.printConfiguration();
}


// ============================================================================
// 10. Lease timing
// ============================================================================

void demonstrateLeaseTimers(
    DHCPClient& client,
    SimulationClock& clock,
    int leaseSeconds
) {
    cout << "\n"
         << string(80, '=')
         << "\nLEASE TIMER STATE MACHINE\n"
         << string(80, '=')
         << "\n";

    const vector<pair<string, double>> checkpoints = {
        {"25%", 0.25},
        {"50%", 0.50},
        {"87.5%", 0.875},
        {"100%", 1.00}
    };

    for (const auto& [label, fraction] : checkpoints) {
        /*
         * This is a simulation, so the clock is advanced by a calculated
         * amount rather than waiting in real time.
         */
        clock.advance(
            static_cast<long long>(
                leaseSeconds * fraction
            ) -
            (fraction == 0.25 ? 0 : 0)
        );

        client.updateLeaseState(clock);

        cout
            << left
            << setw(8)
            << label
            << " -> "
            << clientStateToString(client.state())
            << "\n";
    }
}


// ============================================================================
// 11. Pool exhaustion
// ============================================================================

void demonstratePoolExhaustion(
    SimulationClock& clock
) {
    cout << "\n"
         << string(80, '=')
         << "\nPOOL EXHAUSTION\n"
         << string(80, '=')
         << "\n";

    DHCPServer server(
        "192.168.50.1",
        {
            "192.168.50.10",
            "192.168.50.11"
        },
        "255.255.255.0",
        "192.168.50.1",
        {"192.168.50.1"},
        120,
        clock
    );

    for (int index = 1; index <= 3; ++index) {
        ostringstream mac;
        mac << "00:00:00:50:00:"
            << hex
            << setw(2)
            << setfill('0')
            << index;

        DHCPClient client(mac.str());

        DHCPPacket discover =
            client.createDiscover();

        try {
            DHCPPacket offer =
                server.receiveDiscover(discover);

            DHCPPacket request =
                client.createRequest(offer);

            DHCPPacket response =
                server.receiveRequest(request);

            if (
                response.messageType ==
                DHCPMessageType::Ack
            ) {
                client.processResponse(
                    response,
                    clock
                );

                cout
                    << client.macAddress()
                    << " assigned an address.\n";
            }
        } catch (const exception& error) {
            cout
                << client.macAddress()
                << " -> "
                << error.what()
                << "\n";
        }
    }

    server.printLeaseTable();
}


// ============================================================================
// 12. Rogue DHCP detection
// ============================================================================

void demonstrateRogueDhcp(
    DHCPServer& legitimateServer,
    DHCPServer& rogueServer
) {
    cout << "\n"
         << string(80, '=')
         << "\nROGUE DHCP DETECTION CASE STUDY\n"
         << string(80, '=')
         << "\n";

    DHCPClient client(
        "aa:bb:cc:dd:ee:99"
    );

    DHCPPacket discover =
        client.createDiscover();

    vector<DHCPServer*> servers = {
        &legitimateServer,
        &rogueServer
    };

    vector<DHCPPacket> offers =
        NetworkSimulator::collectOffers(
            servers,
            discover
        );

    cout << "\nReceived "
         << offers.size()
         << " DHCP offer(s).\n";

    for (const DHCPPacket& offer : offers) {
        cout << "\n"
             << offer.summary()
             << "\n";

        cout << "Server:  "
             << offer.serverIdentifier.value_or("unknown")
             << "\n";

        cout << "Address: "
             << offer.offeredIp.value_or("unknown")
             << "\n";

        cout << "Gateway: "
             << offer.router.value_or("unknown")
             << "\n";

        cout << "DNS:     ";

        for (size_t index = 0;
             index < offer.dnsServers.size();
             ++index) {
            if (index != 0) {
                cout << ", ";
            }

            cout << offer.dnsServers[index];
        }

        cout << "\n";
    }

    set<string> trustedServerIds = {
        legitimateServer.identifier()
    };

    vector<OfferObservation> findings =
        NetworkSimulator::analyzeOffers(
            offers,
            trustedServerIds
        );

    cout << "\nSecurity analysis:\n";

    for (const auto& finding : findings) {
        cout
            << "UNEXPECTED DHCP SERVER: "
            << finding.serverIdentifier
            << "\n"
            << "Offered IP: "
            << finding.offeredIp
            << "\n"
            << "Gateway: "
            << finding.gateway
            << "\n";
    }

    if (findings.empty()) {
        cout
            << "No unexpected DHCP server found.\n";
    }
}


// ============================================================================
// 13. Invalid request demonstration
// ============================================================================

void demonstrateInvalidRequest(
    DHCPServer& server
) {
    cout << "\n"
         << string(80, '=')
         << "\nINVALID REQUEST VALIDATION\n"
         << string(80, '=')
         << "\n";

    DHCPPacket request;

    request.messageType =
        DHCPMessageType::Request;

    request.transactionId = 0xDEADBEEF;

    request.clientMac =
        "de:ad:be:ef:00:01";

    request.requestedIp =
        "10.10.10.10";

    request.serverIdentifier =
        server.identifier();

    DHCPPacket response =
        server.receiveRequest(request);

    cout
        << "Requested address: "
        << request.requestedIp.value()
        << "\n";

    cout
        << "Server response: "
        << messageTypeToString(
            response.messageType
        )
        << "\n";
}


// ============================================================================
// 14. Security architecture discussion
// ============================================================================

void printSecurityControls() {
    cout << "\n"
         << string(80, '=')
         << "\nDHCP SECURITY CONTROLS\n"
         << string(80, '=')
         << "\n";

    const vector<pair<string, string>> controls = {
        {
            "DHCP snooping",
            "Switch mechanism that can identify trusted DHCP "
            "server-facing interfaces and restrict unauthorized "
            "DHCP responses."
        },
        {
            "Trusted interfaces",
            "Only authorized DHCP servers or relays should normally "
            "send DHCP server responses into a protected access domain."
        },
        {
            "Network monitoring",
            "Unexpected server identifiers, gateways, DNS servers, "
            "or DHCP traffic patterns can be investigated."
        },
        {
            "Segmentation",
            "VLANs and routing boundaries can limit the broadcast "
            "domain in which DHCP discovery operates."
        }
    };

    for (const auto& [control, purpose] : controls) {
        cout
            << "\n"
            << control
            << "\n"
            << purpose
            << "\n";
    }

    cout
        << "\nWireshark provides packet visibility and analysis. "
        << "It does not itself enforce DHCP authorization.\n";
}


// ============================================================================
// 15. Main program
// ============================================================================

int main() {
    try {
        cout
            << string(80, '=')
            << "\nDHCP ENTERPRISE NETWORK CASE STUDY\n"
            << string(80, '=')
            << "\n";

        SimulationClock clock;

        DHCPServer legitimateServer(
            "192.168.10.1",
            {
                "192.168.10.100",
                "192.168.10.101",
                "192.168.10.102",
                "192.168.10.103"
            },
            "255.255.255.0",
            "192.168.10.1",
            {
                "192.168.10.1",
                "1.1.1.1"
            },
            3600,
            clock
        );

        DHCPClient client(
            "aa:bb:cc:dd:ee:01"
        );

        demonstrateDora(
            legitimateServer,
            client,
            clock
        );

        legitimateServer.printLeaseTable();

        /*
         * In a real client, T1 and T2 are lease timers. The common default
         * behavior is approximately:
         *
         * T1 = 50% of lease
         * T2 = 87.5% of lease
         *
         * The exact implementation can depend on the lease configuration
         * and client/server behavior.
         */
        cout
            << "\nLease timer concept: "
            << "T1 approximately 50%, "
            << "T2 approximately 87.5%.\n";

        DHCPServer rogueServer(
            "192.168.10.254",
            {
                "192.168.10.200",
                "192.168.10.201"
            },
            "255.255.255.0",
            "192.168.10.254",
            {
                "192.168.10.254"
            },
            7200,
            clock
        );

        demonstrateRogueDhcp(
            legitimateServer,
            rogueServer
        );

        printWiresharkFilters();

        /*
         * The next packet is not captured from a network interface. It is
         * a model of what Wireshark would expose as DHCP fields.
         */
        DHCPPacket analysisPacket;

        analysisPacket.messageType =
            DHCPMessageType::Offer;

        analysisPacket.transactionId =
            0x12345678;

        analysisPacket.clientMac =
            "aa:bb:cc:dd:ee:01";

        analysisPacket.sourceIp =
            "192.168.10.1";

        analysisPacket.destinationIp =
            "255.255.255.255";

        analysisPacket.serverIdentifier =
            "192.168.10.1";

        analysisPacket.offeredIp =
            "192.168.10.100";

        analysisPacket.subnetMask =
            "255.255.255.0";

        analysisPacket.router =
            "192.168.10.1";

        analysisPacket.dnsServers =
            {"192.168.10.1", "1.1.1.1"};

        analysisPacket.leaseSeconds =
            3600;

        printPacketAnalysis(
            analysisPacket
        );

        demonstrateInvalidRequest(
            legitimateServer
        );

        demonstratePoolExhaustion(
            clock
        );

        printSecurityControls();

        cout
            << "\n"
            << string(80, '=')
            << "\nPROTOCOL MESSAGE TABLE\n"
            << string(80, '=')
            << "\n";

        const vector<tuple<string, string, string>> messages = {
            {
                "DHCPDISCOVER",
                "Client",
                "Searches for available DHCP servers."
            },
            {
                "DHCPOFFER",
                "Server",
                "Proposes an IP address and network configuration."
            },
            {
                "DHCPREQUEST",
                "Client",
                "Selects an offer and requests the configuration."
            },
            {
                "DHCPACK",
                "Server",
                "Confirms the address lease and configuration."
            },
            {
                "DHCPNAK",
                "Server",
                "Rejects an invalid or unacceptable request."
            },
            {
                "DHCPDECLINE",
                "Client",
                "Reports that an offered address appears unusable."
            },
            {
                "DHCPRELEASE",
                "Client",
                "Returns a lease before expiration."
            },
            {
                "DHCPINFORM",
                "Client",
                "Requests configuration information without obtaining "
                "a new address lease."
            }
        };

        for (
            const auto& [message, sender, meaning]
            : messages
        ) {
            cout
                << left
                << setw(16)
                << message
                << setw(10)
                << sender
                << meaning
                << "\n";
        }

        cout
            << "\nCase-study architecture:\n"
            << "Client -> broadcast discovery -> DHCP servers -> offers\n"
            << "Client -> selected server -> request -> ACK/NAK\n"
            << "Lease database -> allocation state\n"
            << "Packet analysis -> Wireshark-style observations\n"
            << "Security analysis -> trusted versus unexpected servers\n";

        return 0;
    } catch (const exception& error) {
        cerr
            << "\nFatal error: "
            << error.what()
            << "\n";

        return 1;
    }
}
