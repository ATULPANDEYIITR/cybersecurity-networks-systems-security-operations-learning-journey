/*
    Nmap Fundamentals: C++17 Case Study

    Scenario:
        A security operations team needs a small internal inventory utility
        for a machine it owns. The utility checks selected TCP and UDP ports,
        records the observed state, performs simple application-level service
        probes, and produces a structured report.

    This is an educational implementation of concepts associated with Nmap.
    It is not a replacement for Nmap.

    Default target:
        127.0.0.1

    Build:
        Linux/macOS:
            g++ -std=c++17 -O2 -Wall -Wextra -pedantic nmap_case_study.cpp -o nmap_case_study

        Windows with MinGW:
            g++ -std=c++17 -O2 -Wall -Wextra -pedantic nmap_case_study.cpp -lws2_32 -o nmap_case_study.exe

    Run:
        ./nmap_case_study
        ./nmap_case_study 127.0.0.1

    Network scanning should only be performed against systems for which
    explicit authorization exists.
*/

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
    #define NOMINMAX
    #include <winsock2.h>
    #include <ws2tcpip.h>
    using SocketHandle = SOCKET;
    constexpr SocketHandle INVALID_SOCKET_HANDLE = INVALID_SOCKET;
#else
    #include <arpa/inet.h>
    #include <cerrno>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/select.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <unistd.h>
    using SocketHandle = int;
    constexpr SocketHandle INVALID_SOCKET_HANDLE = -1;
#endif

namespace nmap_case_study {

// -----------------------------------------------------------------------------
// Platform abstraction
// -----------------------------------------------------------------------------

void closeSocket(SocketHandle socketHandle) {
#ifdef _WIN32
    closesocket(socketHandle);
#else
    close(socketHandle);
#endif
}

std::string socketError() {
#ifdef _WIN32
    return std::to_string(WSAGetLastError());
#else
    return std::strerror(errno);
#endif
}

bool initializeNetworking() {
#ifdef _WIN32
    WSADATA data{};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return true;
#endif
}

void cleanupNetworking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// -----------------------------------------------------------------------------
// Domain model
// -----------------------------------------------------------------------------

enum class PortState {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
    Error
};

std::string stateToString(PortState state) {
    switch (state) {
        case PortState::Open:
            return "open";
        case PortState::Closed:
            return "closed";
        case PortState::Filtered:
            return "filtered";
        case PortState::OpenOrFiltered:
            return "open|filtered";
        case PortState::Error:
            return "error";
    }

    return "unknown";
}

struct ScanResult {
    int port{};
    std::string protocol;
    PortState state{PortState::Error};
    std::string service;
    std::string observation;
    double latencyMilliseconds{};
};

// -----------------------------------------------------------------------------
// Service identification
// -----------------------------------------------------------------------------

const std::map<int, std::string> COMMON_SERVICES{
    {20, "ftp-data"},
    {21, "ftp"},
    {22, "ssh"},
    {23, "telnet"},
    {25, "smtp"},
    {53, "dns"},
    {67, "dhcp-server"},
    {68, "dhcp-client"},
    {80, "http"},
    {110, "pop3"},
    {111, "rpcbind"},
    {123, "ntp"},
    {135, "msrpc"},
    {137, "netbios-ns"},
    {138, "netbios-dgm"},
    {139, "netbios-ssn"},
    {143, "imap"},
    {161, "snmp"},
    {389, "ldap"},
    {443, "https"},
    {445, "microsoft-ds"},
    {587, "submission"},
    {636, "ldaps"},
    {993, "imaps"},
    {995, "pop3s"},
    {1433, "mssql"},
    {1521, "oracle"},
    {2049, "nfs"},
    {3306, "mysql"},
    {3389, "rdp"},
    {5432, "postgresql"},
    {5900, "vnc"},
    {6379, "redis"},
    {8080, "http-alt"}
};

std::string serviceName(int port) {
    const auto iterator = COMMON_SERVICES.find(port);

    if (iterator == COMMON_SERVICES.end()) {
        return "unknown";
    }

    return iterator->second;
}

// -----------------------------------------------------------------------------
// Address resolution
// -----------------------------------------------------------------------------

std::optional<sockaddr_in> resolveIPv4(const std::string& hostname) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;

    const int status = getaddrinfo(
        hostname.c_str(),
        nullptr,
        &hints,
        &result
    );

    if (status != 0 || result == nullptr) {
        return std::nullopt;
    }

    sockaddr_in address =
        *reinterpret_cast<sockaddr_in*>(result->ai_addr);

    freeaddrinfo(result);
    return address;
}

// -----------------------------------------------------------------------------
// TCP connect scanner
// -----------------------------------------------------------------------------

ScanResult tcpConnectScan(
    const std::string& target,
    int port,
    int timeoutMilliseconds
) {
    const auto started = std::chrono::steady_clock::now();

    ScanResult result;
    result.port = port;
    result.protocol = "tcp";
    result.service = serviceName(port);

    const auto resolvedAddress = resolveIPv4(target);

    if (!resolvedAddress.has_value()) {
        result.state = PortState::Error;
        result.observation = "Target could not be resolved.";
        return result;
    }

    SocketHandle socketHandle = socket(AF_INET, SOCK_STREAM, 0);

    if (socketHandle == INVALID_SOCKET_HANDLE) {
        result.state = PortState::Error;
        result.observation = "Socket creation failed: " + socketError();
        return result;
    }

    sockaddr_in destination = resolvedAddress.value();
    destination.sin_port = htons(static_cast<uint16_t>(port));

    /*
        A blocking connect can wait for a long time on filtered hosts.
        We use non-blocking mode plus select() to enforce a controlled timeout.
    */
#ifdef _WIN32
    u_long nonBlocking = 1;
    ioctlsocket(socketHandle, FIONBIO, &nonBlocking);
#else
    const int flags = fcntl(socketHandle, F_GETFL, 0);
    fcntl(socketHandle, F_SETFL, flags | O_NONBLOCK);
#endif

    const int connectResult = connect(
        socketHandle,
        reinterpret_cast<sockaddr*>(&destination),
        sizeof(destination)
    );

    bool open = false;
    bool timeout = false;

    if (connectResult == 0) {
        open = true;
    } else {
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(socketHandle, &writeSet);

        timeval waitTime{};
        waitTime.tv_sec = timeoutMilliseconds / 1000;
        waitTime.tv_usec = (timeoutMilliseconds % 1000) * 1000;

#ifdef _WIN32
        const int ready = select(
            0,
            nullptr,
            &writeSet,
            nullptr,
            &waitTime
        );
#else
        const int ready = select(
            socketHandle + 1,
            nullptr,
            &writeSet,
            nullptr,
            &waitTime
        );
#endif

        if (ready == 0) {
            timeout = true;
        } else if (ready > 0) {
            int socketErrorValue = 0;
            socklen_t errorLength = sizeof(socketErrorValue);

#ifdef _WIN32
            getsockopt(
                socketHandle,
                SOL_SOCKET,
                SO_ERROR,
                reinterpret_cast<char*>(&socketErrorValue),
                &errorLength
            );
#else
            getsockopt(
                socketHandle,
                SOL_SOCKET,
                SO_ERROR,
                &socketErrorValue,
                &errorLength
            );
#endif

            if (socketErrorValue == 0) {
                open = true;
            }
        }
    }

    closeSocket(socketHandle);

    const auto finished = std::chrono::steady_clock::now();

    result.latencyMilliseconds =
        std::chrono::duration<double, std::milli>(
            finished - started
        ).count();

    if (open) {
        result.state = PortState::Open;
        result.observation = "TCP connection succeeded.";
    } else if (timeout) {
        result.state = PortState::Filtered;
        result.observation =
            "No TCP response before timeout; filtering is possible.";
    } else {
        result.state = PortState::Closed;
        result.observation =
            "TCP connection was not established.";
    }

    return result;
}

// -----------------------------------------------------------------------------
// HTTP service detection
// -----------------------------------------------------------------------------

std::string detectHttpService(
    const std::string& target,
    int port,
    int timeoutMilliseconds
) {
    const auto resolvedAddress = resolveIPv4(target);

    if (!resolvedAddress.has_value()) {
        return "";
    }

    SocketHandle socketHandle = socket(AF_INET, SOCK_STREAM, 0);

    if (socketHandle == INVALID_SOCKET_HANDLE) {
        return "";
    }

    sockaddr_in destination = resolvedAddress.value();
    destination.sin_port = htons(static_cast<uint16_t>(port));

    if (connect(
            socketHandle,
            reinterpret_cast<sockaddr*>(&destination),
            sizeof(destination)
        ) != 0) {
        closeSocket(socketHandle);
        return "";
    }

    const std::string request =
        "HEAD / HTTP/1.0\r\n"
        "Host: " + target + "\r\n"
        "Connection: close\r\n"
        "\r\n";

    const int sent = send(
        socketHandle,
        request.data(),
        static_cast<int>(request.size()),
        0
    );

    if (sent <= 0) {
        closeSocket(socketHandle);
        return "";
    }

    /*
        select() keeps application-level probing bounded. A service that does
        not answer the HTTP request is not automatically classified as broken.
    */
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(socketHandle, &readSet);

    timeval waitTime{};
    waitTime.tv_sec = timeoutMilliseconds / 1000;
    waitTime.tv_usec = (timeoutMilliseconds % 1000) * 1000;

#ifdef _WIN32
    const int ready = select(
        0,
        &readSet,
        nullptr,
        nullptr,
        &waitTime
    );
#else
    const int ready = select(
        socketHandle + 1,
        &readSet,
        nullptr,
        nullptr,
        &waitTime
    );
#endif

    if (ready <= 0) {
        closeSocket(socketHandle);
        return "";
    }

    std::array<char, 2048> buffer{};
    const int received = recv(
        socketHandle,
        buffer.data(),
        static_cast<int>(buffer.size() - 1),
        0
    );

    closeSocket(socketHandle);

    if (received <= 0) {
        return "";
    }

    std::string response(buffer.data(), received);

    const auto firstLineEnd = response.find('\n');

    if (firstLineEnd == std::string::npos) {
        return response.substr(0, 200);
    }

    std::string firstLine = response.substr(0, firstLineEnd);

    if (!firstLine.empty() && firstLine.back() == '\r') {
        firstLine.pop_back();
    }

    return firstLine;
}

// -----------------------------------------------------------------------------
// Lightweight service detection
// -----------------------------------------------------------------------------

void performServiceDetection(
    const std::string& target,
    std::vector<ScanResult>& results,
    int timeoutMilliseconds
) {
    for (auto& result : results) {
        if (result.protocol != "tcp" ||
            result.state != PortState::Open) {
            continue;
        }

        if (result.port == 80 || result.port == 8080) {
            const std::string response =
                detectHttpService(
                    target,
                    result.port,
                    std::max(timeoutMilliseconds, 1000)
                );

            if (!response.empty()) {
                result.observation += " HTTP: " + response;
            }
        }
    }
}

// -----------------------------------------------------------------------------
// UDP probe
// -----------------------------------------------------------------------------

ScanResult udpProbe(
    const std::string& target,
    int port,
    int timeoutMilliseconds
) {
    const auto started = std::chrono::steady_clock::now();

    ScanResult result;
    result.port = port;
    result.protocol = "udp";
    result.service = serviceName(port);

    const auto resolvedAddress = resolveIPv4(target);

    if (!resolvedAddress.has_value()) {
        result.state = PortState::Error;
        result.observation = "Target could not be resolved.";
        return result;
    }

    SocketHandle socketHandle = socket(AF_INET, SOCK_DGRAM, 0);

    if (socketHandle == INVALID_SOCKET_HANDLE) {
        result.state = PortState::Error;
        result.observation = "UDP socket creation failed.";
        return result;
    }

    sockaddr_in destination = resolvedAddress.value();
    destination.sin_port = htons(static_cast<uint16_t>(port));

    /*
        DNS is a useful educational example because an actual DNS query can
        produce an application-level response. For other ports, a zero-byte
        UDP datagram illustrates the ambiguity of UDP scanning.
    */
    std::vector<unsigned char> payload;

    if (port == 53) {
        payload = {
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
            0x00, 0x01,
            0x00, 0x01
        };
    }

    const int sent = sendto(
        socketHandle,
        reinterpret_cast<const char*>(payload.data()),
        static_cast<int>(payload.size()),
        0,
        reinterpret_cast<sockaddr*>(&destination),
        sizeof(destination)
    );

    if (sent < 0) {
        closeSocket(socketHandle);

        result.state = PortState::Error;
        result.observation = "UDP send failed: " + socketError();
        return result;
    }

    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(socketHandle, &readSet);

    timeval waitTime{};
    waitTime.tv_sec = timeoutMilliseconds / 1000;
    waitTime.tv_usec = (timeoutMilliseconds % 1000) * 1000;

#ifdef _WIN32
    const int ready = select(
        0,
        &readSet,
        nullptr,
        nullptr,
        &waitTime
    );
#else
    const int ready = select(
        socketHandle + 1,
        &readSet,
        nullptr,
        nullptr,
        &waitTime
    );
#endif

    const auto finished = std::chrono::steady_clock::now();

    result.latencyMilliseconds =
        std::chrono::duration<double, std::milli>(
            finished - started
        ).count();

    if (ready > 0) {
        std::array<char, 4096> buffer{};

        sockaddr_in sender{};
#ifdef _WIN32
        int senderLength = sizeof(sender);
#else
        socklen_t senderLength = sizeof(sender);
#endif

        const int received = recvfrom(
            socketHandle,
            buffer.data(),
            static_cast<int>(buffer.size()),
            0,
            reinterpret_cast<sockaddr*>(&sender),
            &senderLength
        );

        if (received > 0) {
            result.state = PortState::Open;
            result.observation =
                "UDP application response received.";
        } else {
            result.state = PortState::OpenOrFiltered;
            result.observation =
                "No usable UDP payload was received.";
        }
    } else if (ready == 0) {
        /*
            Critical UDP principle:
            silence is not equivalent to "open".
        */
        result.state = PortState::OpenOrFiltered;
        result.observation =
            "No UDP response; open and filtered cannot be distinguished.";
    } else {
        result.state = PortState::Error;
        result.observation = "UDP wait operation failed.";
    }

    closeSocket(socketHandle);
    return result;
}

// -----------------------------------------------------------------------------
// Concurrent scan orchestration
// -----------------------------------------------------------------------------

std::vector<ScanResult> scanTcpPorts(
    const std::string& target,
    const std::vector<int>& ports,
    int timeoutMilliseconds
) {
    std::vector<std::future<ScanResult>> futures;

    for (const int port : ports) {
        futures.push_back(
            std::async(
                std::launch::async,
                tcpConnectScan,
                target,
                port,
                timeoutMilliseconds
            )
        );
    }

    std::vector<ScanResult> results;
    results.reserve(futures.size());

    for (auto& future : futures) {
        results.push_back(future.get());
    }

    return results;
}

std::vector<ScanResult> scanUdpPorts(
    const std::string& target,
    const std::vector<int>& ports,
    int timeoutMilliseconds
) {
    std::vector<std::future<ScanResult>> futures;

    for (const int port : ports) {
        futures.push_back(
            std::async(
                std::launch::async,
                udpProbe,
                target,
                port,
                timeoutMilliseconds
            )
        );
    }

    std::vector<ScanResult> results;
    results.reserve(futures.size());

    for (auto& future : futures) {
        results.push_back(future.get());
    }

    return results;
}

// -----------------------------------------------------------------------------
// Reporting
// -----------------------------------------------------------------------------

void printResults(const std::vector<ScanResult>& results) {
    std::vector<ScanResult> sorted = results;

    std::sort(
        sorted.begin(),
        sorted.end(),
        [](const ScanResult& first, const ScanResult& second) {
            if (first.protocol != second.protocol) {
                return first.protocol < second.protocol;
            }

            return first.port < second.port;
        }
    );

    std::cout << "\n";
    std::cout << std::string(100, '=') << "\n";
    std::cout << "SCAN RESULTS\n";
    std::cout << std::string(100, '=') << "\n";

    std::cout
        << std::right
        << std::setw(7) << "PORT"
        << std::setw(9) << "PROTO"
        << std::setw(18) << "STATE"
        << std::setw(28) << "SERVICE"
        << std::setw(14) << "LATENCY"
        << "\n";

    std::cout << std::string(100, '-') << "\n";

    for (const auto& result : sorted) {
        std::cout
            << std::setw(7) << result.port
            << std::setw(9) << result.protocol
            << std::setw(18) << stateToString(result.state)
            << std::setw(28) << result.service.substr(0, 27)
            << std::setw(11)
            << std::fixed
            << std::setprecision(2)
            << result.latencyMilliseconds
            << " ms\n";

        std::cout << "        " << result.observation << "\n";
    }
}

// -----------------------------------------------------------------------------
// Nmap reference
// -----------------------------------------------------------------------------

void printNmapReference(
    const std::string& target,
    const std::string& ports
) {
    std::cout << "\n";
    std::cout << std::string(100, '=') << "\n";
    std::cout << "NMAP COMMAND REFERENCE\n";
    std::cout << std::string(100, '=') << "\n";

    std::cout
        << "nmap -sT -p " << ports << " " << target
        << "    -> TCP connect scan\n";

    std::cout
        << "nmap -sU -p " << ports << " " << target
        << "    -> UDP scan\n";

    std::cout
        << "nmap -sT -sV -p " << ports << " " << target
        << "    -> Service/version detection\n";

    std::cout
        << "nmap -O -p " << ports << " " << target
        << "    -> OS detection\n";

    std::cout
        << "nmap -sT -sV -O -p " << ports << " " << target
        << "    -> Combined example\n";
}

// -----------------------------------------------------------------------------
// Educational explanations
// -----------------------------------------------------------------------------

void explainConcepts() {
    std::cout << "NMAP FUNDAMENTALS CASE STUDY\n";
    std::cout << std::string(100, '=') << "\n\n";

    std::cout
        << "TCP scanning:\n"
        << "A successful TCP connection provides strong evidence that a\n"
        << "service is listening. Connection refusal normally indicates\n"
        << "a reachable host with no listener on that port.\n\n";

    std::cout
        << "UDP scanning:\n"
        << "UDP has no TCP-style handshake. A response may identify an open\n"
        << "service, while silence often leaves open and filtered ambiguous.\n\n";

    std::cout
        << "Service detection:\n"
        << "Port numbers are hints, not proof. Application-layer probes can\n"
        << "provide stronger evidence about the actual service.\n\n";

    std::cout
        << "OS detection:\n"
        << "Nmap uses network fingerprints, including TCP/IP response behavior,\n"
        << "to infer operating-system families. The inference can be uncertain.\n\n";

    std::cout
        << "Production trade-off:\n"
        << "Timeouts, concurrency, retries, packet rate, accuracy, and network\n"
        << "load must be balanced rather than maximizing scan speed blindly.\n\n";
}

// -----------------------------------------------------------------------------
// Main case study
// -----------------------------------------------------------------------------

int runCaseStudy(const std::string& target) {
    /*
        The deliberately small port set keeps the example appropriate for
        local study. It can discover common services without automatically
        sweeping an entire address range.
    */
    const std::vector<int> ports{
        22, 53, 80, 443, 8080
    };

    constexpr int timeoutMilliseconds = 700;

    explainConcepts();

    std::cout << "Target: " << target << "\n";
    std::cout << "Ports: ";

    for (std::size_t index = 0; index < ports.size(); ++index) {
        if (index != 0) {
            std::cout << ", ";
        }

        std::cout << ports[index];
    }

    std::cout << "\n\n";

    std::cout << "Stage 1: TCP connect scan\n";

    auto tcpResults = scanTcpPorts(
        target,
        ports,
        timeoutMilliseconds
    );

    performServiceDetection(
        target,
        tcpResults,
        timeoutMilliseconds
    );

    std::cout << "Stage 2: UDP probe scan\n";

    auto udpResults = scanUdpPorts(
        target,
        ports,
        timeoutMilliseconds
    );

    std::vector<ScanResult> combined;
    combined.reserve(tcpResults.size() + udpResults.size());

    combined.insert(
        combined.end(),
        tcpResults.begin(),
        tcpResults.end()
    );

    combined.insert(
        combined.end(),
        udpResults.begin(),
        udpResults.end()
    );

    printResults(combined);

    printNmapReference(
        target,
        "22,53,80,443,8080"
    );

    std::cout << "\n";
    std::cout
        << "Important: this program demonstrates network scanning concepts;\n"
        << "it is not a replacement for Nmap's packet-level fingerprinting,\n"
        << "service-probe database, OS database, retransmission logic,\n"
        << "host discovery system, or mature reporting engine.\n";

    return 0;
}

} // namespace nmap_case_study

// -----------------------------------------------------------------------------
// Program entry point
// -----------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    if (!nmap_case_study::initializeNetworking()) {
        std::cerr << "Network initialization failed.\n";
        return 1;
    }

    /*
        Defaulting to loopback reduces accidental scanning of unrelated
        systems. A different target should only be supplied when the caller
        is authorized to scan it.
    */
    std::string target = "127.0.0.1";

    if (argc >= 2) {
        target = argv[1];
    }

    const int result = nmap_case_study::runCaseStudy(target);

    nmap_case_study::cleanupNetworking();
    return result;
}
