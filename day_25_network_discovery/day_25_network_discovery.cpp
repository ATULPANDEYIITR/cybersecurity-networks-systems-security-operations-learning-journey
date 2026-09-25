/*
 * Network Discovery Case Study
 *
 * Scenario:
 *   An organization needs a small internal asset-inventory component that
 *   verifies whether explicitly authorized hosts expose selected TCP services.
 *
 * This C++17 program demonstrates:
 *   - IPv4 address validation
 *   - TCP socket programming
 *   - service/port classification
 *   - connection timeouts
 *   - passive banner collection
 *   - reverse DNS
 *   - structured inventory records
 *   - concurrent host processing
 *   - JSON-like report generation without external libraries
 *   - validation and failure handling
 *   - complexity and architectural trade-offs
 *
 * Platform:
 *   POSIX/Linux/macOS style sockets.
 *
 * Build:
 *   g++ -std=c++17 -O2 -pthread network_discovery.cpp -o network_discovery
 *
 * Windows users can adapt the socket layer to Winsock2. The standard library
 * data structures and higher-level architecture remain applicable.
 *
 * Use only against systems and networks that you own or are explicitly
 * authorized to test.
 *
 * This program does not implement stealth, evasion, exploitation,
 * credential attacks, or vulnerability exploitation.
 */

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <netdb.h>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <algorithm>

namespace network_discovery {

// ---------------------------------------------------------------------------
// Fundamental data structures
// ---------------------------------------------------------------------------

struct PortResult {
    int port{};
    std::string protocol{"tcp"};
    std::string state{"unknown"};
    std::string service_guess{"unknown"};
    std::string banner;
    double latency_ms{0.0};
    std::string error;
};

struct HostResult {
    std::string ip;
    bool reachable{false};
    std::string reverse_dns;
    double latency_ms{0.0};
    std::vector<PortResult> ports;
};

struct NetworkMap {
    std::string target;
    std::vector<HostResult> hosts;
    std::string created_at;
};

// ---------------------------------------------------------------------------
// Service classification
// ---------------------------------------------------------------------------

const std::map<int, std::string> COMMON_SERVICES = {
    {20, "FTP-DATA"},
    {21, "FTP"},
    {22, "SSH"},
    {23, "TELNET"},
    {25, "SMTP"},
    {53, "DNS"},
    {80, "HTTP"},
    {110, "POP3"},
    {123, "NTP"},
    {135, "MS-RPC"},
    {139, "NETBIOS-SSN"},
    {143, "IMAP"},
    {161, "SNMP"},
    {389, "LDAP"},
    {443, "HTTPS"},
    {445, "SMB"},
    {587, "SMTP-SUBMISSION"},
    {631, "IPP"},
    {636, "LDAPS"},
    {993, "IMAPS"},
    {995, "POP3S"},
    {1433, "MSSQL"},
    {1521, "ORACLE"},
    {2049, "NFS"},
    {2375, "DOCKER"},
    {3306, "MYSQL"},
    {3389, "RDP"},
    {5432, "POSTGRESQL"},
    {5900, "VNC"},
    {6379, "REDIS"},
    {8080, "HTTP-ALT"},
    {8443, "HTTPS-ALT"},
    {9200, "ELASTICSEARCH"}
};

std::string service_guess(int port) {
    auto iterator = COMMON_SERVICES.find(port);

    if (iterator == COMMON_SERVICES.end()) {
        return "unknown";
    }

    return iterator->second;
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

std::string current_time_utc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t timestamp =
        std::chrono::system_clock::to_time_t(now);

    std::tm utc{};
    gmtime_r(&timestamp, &utc);

    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");

    return output.str();
}

std::string trim_banner(const std::string& input) {
    /*
     * Banner data comes from the network and must be treated as untrusted.
     * Limit output to printable ASCII plus common whitespace characters.
     */
    std::string result;

    for (unsigned char character : input) {
        if (
            character == '\n' ||
            character == '\r' ||
            character == '\t' ||
            (character >= 32 && character <= 126)
        ) {
            result.push_back(static_cast<char>(character));
        }
    }

    while (
        !result.empty() &&
        (result.back() == '\n' ||
         result.back() == '\r' ||
         result.back() == ' ' ||
         result.back() == '\t')
    ) {
        result.pop_back();
    }

    return result;
}

bool valid_port(int port) {
    return port >= 1 && port <= 65535;
}

// ---------------------------------------------------------------------------
// IPv4 validation
// ---------------------------------------------------------------------------

bool valid_ipv4(const std::string& address) {
    sockaddr_in socket_address{};

    return inet_pton(
        AF_INET,
        address.c_str(),
        &socket_address.sin_addr
    ) == 1;
}

// ---------------------------------------------------------------------------
// Reverse DNS
// ---------------------------------------------------------------------------

std::string reverse_dns(const std::string& ip) {
    sockaddr_in address{};
    address.sin_family = AF_INET;

    if (
        inet_pton(
            AF_INET,
            ip.c_str(),
            &address.sin_addr
        ) != 1
    ) {
        return {};
    }

    char hostname[NI_MAXHOST]{};

    const int status = getnameinfo(
        reinterpret_cast<sockaddr*>(&address),
        sizeof(address),
        hostname,
        sizeof(hostname),
        nullptr,
        0,
        NI_NAMEREQD
    );

    if (status != 0) {
        return {};
    }

    return hostname;
}

// ---------------------------------------------------------------------------
// Socket connection helper
// ---------------------------------------------------------------------------

class TcpSocket {
public:
    TcpSocket() = default;

    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    ~TcpSocket() {
        close_socket();
    }

    int get() const {
        return descriptor_;
    }

    bool create() {
        descriptor_ = socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

        return descriptor_ >= 0;
    }

    void close_socket() {
        if (descriptor_ >= 0) {
            close(descriptor_);
            descriptor_ = -1;
        }
    }

private:
    int descriptor_{-1};
};

// ---------------------------------------------------------------------------
// TCP connect with timeout
// ---------------------------------------------------------------------------

PortResult tcp_connect(
    const std::string& ip,
    int port,
    int timeout_ms
) {
    PortResult result;
    result.port = port;
    result.service_guess = service_guess(port);

    if (!valid_ipv4(ip)) {
        result.state = "error";
        result.error = "invalid IPv4 address";
        return result;
    }

    if (!valid_port(port)) {
        result.state = "error";
        result.error = "invalid port";
        return result;
    }

    if (timeout_ms <= 0) {
        result.state = "error";
        result.error = "timeout must be positive";
        return result;
    }

    TcpSocket socket_wrapper;

    if (!socket_wrapper.create()) {
        result.state = "error";
        result.error = std::strerror(errno);
        return result;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(static_cast<uint16_t>(port));

    inet_pton(
        AF_INET,
        ip.c_str(),
        &target.sin_addr
    );

    /*
     * Non-blocking connect allows the program to impose its own timeout
     * instead of potentially waiting for the operating system's default
     * TCP timeout.
     */
    const int original_flags =
        fcntl(socket_wrapper.get(), F_GETFL, 0);

    if (original_flags < 0) {
        result.state = "error";
        result.error = std::strerror(errno);
        return result;
    }

    if (
        fcntl(
            socket_wrapper.get(),
            F_SETFL,
            original_flags | O_NONBLOCK
        ) < 0
    ) {
        result.state = "error";
        result.error = std::strerror(errno);
        return result;
    }

    const auto started =
        std::chrono::steady_clock::now();

    const int connect_result = connect(
        socket_wrapper.get(),
        reinterpret_cast<sockaddr*>(&target),
        sizeof(target)
    );

    if (connect_result == 0) {
        const auto finished =
            std::chrono::steady_clock::now();

        result.latency_ms =
            std::chrono::duration<double, std::milli>(
                finished - started
            ).count();

        result.state = "open";
        return result;
    }

    if (errno != EINPROGRESS) {
        result.state =
            errno == ECONNREFUSED
                ? "closed"
                : "error";

        result.error = std::strerror(errno);
        return result;
    }

    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(socket_wrapper.get(), &writable);

    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    const int selected = select(
        socket_wrapper.get() + 1,
        nullptr,
        &writable,
        nullptr,
        &timeout
    );

    const auto finished =
        std::chrono::steady_clock::now();

    result.latency_ms =
        std::chrono::duration<double, std::milli>(
            finished - started
        ).count();

    if (selected == 0) {
        result.state = "filtered_or_timeout";
        result.error = "connection timed out";
        return result;
    }

    if (selected < 0) {
        result.state = "error";
        result.error = std::strerror(errno);
        return result;
    }

    int socket_error = 0;
    socklen_t error_length = sizeof(socket_error);

    getsockopt(
        socket_wrapper.get(),
        SOL_SOCKET,
        SO_ERROR,
        &socket_error,
        &error_length
    );

    if (socket_error == 0) {
        result.state = "open";
    } else if (socket_error == ECONNREFUSED) {
        result.state = "closed";
        result.error = "connection refused";
    } else {
        result.state = "filtered_or_unreachable";
        result.error = std::strerror(socket_error);
    }

    return result;
}

// ---------------------------------------------------------------------------
// Passive banner collection
// ---------------------------------------------------------------------------

std::string passive_banner(
    const std::string& ip,
    int port,
    int timeout_ms
) {
    /*
     * This function first establishes a normal TCP connection. It then reads
     * data already sent by the server.
     *
     * No arbitrary application-layer payload is transmitted.
     *
     * Some protocols, such as SSH or SMTP, commonly send a greeting.
     * Others, such as many HTTP servers, wait for a request and therefore
     * produce no passive banner.
     */
    TcpSocket socket_wrapper;

    if (!socket_wrapper.create()) {
        return {};
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(static_cast<uint16_t>(port));

    if (
        inet_pton(
            AF_INET,
            ip.c_str(),
            &target.sin_addr
        ) != 1
    ) {
        return {};
    }

    if (
        connect(
            socket_wrapper.get(),
            reinterpret_cast<sockaddr*>(&target),
            sizeof(target)
        ) != 0
    ) {
        return {};
    }

    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(socket_wrapper.get(), &readable);

    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    const int selected = select(
        socket_wrapper.get() + 1,
        &readable,
        nullptr,
        nullptr,
        &timeout
    );

    if (selected <= 0) {
        return {};
    }

    char buffer[512]{};

    const ssize_t bytes_read = recv(
        socket_wrapper.get(),
        buffer,
        sizeof(buffer),
        0
    );

    if (bytes_read <= 0) {
        return {};
    }

    return trim_banner(
        std::string(buffer, static_cast<size_t>(bytes_read))
    );
}

// ---------------------------------------------------------------------------
// Service discovery
// ---------------------------------------------------------------------------

std::vector<PortResult> discover_services(
    const std::string& ip,
    const std::vector<int>& ports,
    int timeout_ms,
    bool collect_banners
) {
    std::vector<PortResult> results;

    for (int port : ports) {
        PortResult result =
            tcp_connect(ip, port, timeout_ms);

        if (
            result.state == "open" &&
            collect_banners
        ) {
            result.banner =
                passive_banner(
                    ip,
                    port,
                    timeout_ms
                );
        }

        results.push_back(
            std::move(result)
        );
    }

    return results;
}

// ---------------------------------------------------------------------------
// Host discovery
// ---------------------------------------------------------------------------

HostResult inspect_host(
    const std::string& ip,
    const std::vector<int>& ports,
    int timeout_ms,
    bool collect_banners
) {
    HostResult host;
    host.ip = ip;
    host.reverse_dns = reverse_dns(ip);

    const auto started =
        std::chrono::steady_clock::now();

    /*
     * TCP-based host discovery asks whether at least one selected application
     * endpoint accepts a connection.
     *
     * This differs from ICMP echo discovery and from Nmap's broader discovery
     * engine. A firewall can make a live host appear unconfirmed.
     */
    for (int port : ports) {
        PortResult result =
            tcp_connect(ip, port, timeout_ms);

        if (result.state == "open") {
            host.reachable = true;
            break;
        }
    }

    const auto finished =
        std::chrono::steady_clock::now();

    host.latency_ms =
        std::chrono::duration<double, std::milli>(
            finished - started
        ).count();

    if (host.reachable) {
        host.ports =
            discover_services(
                ip,
                ports,
                timeout_ms,
                collect_banners
            );
    }

    return host;
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

std::vector<HostResult> parallel_inventory(
    const std::vector<std::string>& addresses,
    const std::vector<int>& ports,
    int timeout_ms,
    bool collect_banners
) {
    std::vector<std::future<HostResult>> futures;

    /*
     * This case study uses one asynchronous task per supplied host.
     *
     * For very large inventories, a bounded thread pool is preferable.
     * Unbounded task creation can consume memory and generate excessive
     * traffic.
     */
    for (const std::string& address : addresses) {
        futures.push_back(
            std::async(
                std::launch::async,
                inspect_host,
                address,
                std::cref(ports),
                timeout_ms,
                collect_banners
            )
        );
    }

    std::vector<HostResult> results;

    for (auto& future : futures) {
        results.push_back(
            future.get()
        );
    }

    std::sort(
        results.begin(),
        results.end(),
        [](const HostResult& left, const HostResult& right) {
            return left.ip < right.ip;
        }
    );

    return results;
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

void print_host(const HostResult& host) {
    std::cout
        << std::left
        << std::setw(16)
        << host.ip
        << std::setw(18)
        << (host.reachable ? "UP" : "NOT CONFIRMED")
        << "DNS="
        << (host.reverse_dns.empty()
                ? "-"
                : host.reverse_dns)
        << '\n';

    std::cout
        << "  latency: "
        << std::fixed
        << std::setprecision(2)
        << host.latency_ms
        << " ms\n";

    for (const PortResult& port : host.ports) {
        std::string banner =
            port.banner.empty()
                ? "-"
                : port.banner;

        std::replace(
            banner.begin(),
            banner.end(),
            '\n',
            ' '
        );

        std::cout
            << "  TCP/"
            << std::setw(5)
            << port.port
            << std::setw(24)
            << port.state
            << std::setw(20)
            << port.service_guess
            << "banner="
            << banner
            << '\n';
    }
}

std::string escape_json(const std::string& input) {
    std::ostringstream output;

    for (char character : input) {
        switch (character) {
            case '"':
                output << "\\\"";
                break;
            case '\\':
                output << "\\\\";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                output << character;
        }
    }

    return output.str();
}

void write_json(
    const NetworkMap& network_map,
    const std::string& filename
) {
    std::ofstream output(filename);

    if (!output) {
        throw std::runtime_error(
            "Unable to open output file."
        );
    }

    output << "{\n";
    output << "  \"target\": \""
           << escape_json(network_map.target)
           << "\",\n";

    output << "  \"createdAt\": \""
           << escape_json(network_map.created_at)
           << "\",\n";

    output << "  \"hosts\": [\n";

    for (size_t host_index = 0;
         host_index < network_map.hosts.size();
         ++host_index) {

        const HostResult& host =
            network_map.hosts[host_index];

        output << "    {\n";
        output << "      \"ip\": \""
               << escape_json(host.ip)
               << "\",\n";

        output << "      \"reachable\": "
               << (host.reachable ? "true" : "false")
               << ",\n";

        output << "      \"reverseDns\": \""
               << escape_json(host.reverse_dns)
               << "\",\n";

        output << "      \"latencyMs\": "
               << std::fixed
               << std::setprecision(2)
               << host.latency_ms
               << ",\n";

        output << "      \"ports\": [\n";

        for (size_t port_index = 0;
             port_index < host.ports.size();
             ++port_index) {

            const PortResult& port =
                host.ports[port_index];

            output << "        {\n";
            output << "          \"port\": "
                   << port.port
                   << ",\n";

            output << "          \"protocol\": \""
                   << escape_json(port.protocol)
                   << "\",\n";

            output << "          \"state\": \""
                   << escape_json(port.state)
                   << "\",\n";

            output << "          \"service\": \""
                   << escape_json(port.service_guess)
                   << "\",\n";

            output << "          \"banner\": \""
                   << escape_json(port.banner)
                   << "\",\n";

            output << "          \"error\": \""
                   << escape_json(port.error)
                   << "\"\n";

            output << "        }";

            if (port_index + 1 < host.ports.size()) {
                output << ",";
            }

            output << "\n";
        }

        output << "      ]\n";
        output << "    }";

        if (host_index + 1 < network_map.hosts.size()) {
            output << ",";
        }

        output << "\n";
    }

    output << "  ]\n";
    output << "}\n";
}

// ---------------------------------------------------------------------------
// Educational architecture explanation
// ---------------------------------------------------------------------------

void print_architecture() {
    std::cout
        << "============================================================\n"
        << "NETWORK DISCOVERY CASE STUDY\n"
        << "============================================================\n"
        << "Problem:\n"
        << "  Maintain an authorized inventory of selected TCP services.\n\n"
        << "Pipeline:\n"
        << "  target validation\n"
        << "      -> host discovery\n"
        << "      -> port discovery\n"
        << "      -> service classification\n"
        << "      -> passive banner collection\n"
        << "      -> reverse DNS\n"
        << "      -> structured inventory\n"
        << "      -> report generation\n\n"
        << "Design principles:\n"
        << "  - Separate transport mechanics from reporting.\n"
        << "  - Treat network responses as untrusted input.\n"
        << "  - Use explicit timeouts so failures do not block forever.\n"
        << "  - Bound the target scope in real deployments.\n"
        << "  - Prefer evidence-based states over assumptions.\n\n"
        << "Typical Nmap concepts:\n"
        << "  -sn     host discovery\n"
        << "  -p      selected ports\n"
        << "  -sV     service/version detection\n"
        << "  -O      operating-system detection\n"
        << '\n';
}

// ---------------------------------------------------------------------------
// Main program
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    try {
        print_architecture();

        /*
         * Default target is localhost.
         *
         * This makes running the program immediately safe and useful without
         * requiring an external target.
         */
        std::string target = "127.0.0.1";

        if (argc >= 2) {
            target = argv[1];
        }

        if (!valid_ipv4(target)) {
            std::cerr
                << "Error: target must be a valid IPv4 address.\n";
            return 2;
        }

        /*
         * Keep the demonstration deliberately small. A production inventory
         * system should obtain its target scope from an explicit authorization
         * boundary and enforce that boundary before scanning.
         */
        const std::vector<int> ports = {
            22,
            80,
            443,
            8000,
            8080
        };

        const int timeout_ms = 700;
        const bool collect_banners = true;

        std::cout
            << "Target: "
            << target
            << '\n';

        std::cout
            << "Ports: ";

        for (size_t index = 0;
             index < ports.size();
             ++index) {
            std::cout << ports[index];

            if (index + 1 < ports.size()) {
                std::cout << ", ";
            }
        }

        std::cout << "\n\n";

        NetworkMap network_map;
        network_map.target = target;
        network_map.created_at = current_time_utc();

        const std::vector<std::string> addresses = {
            target
        };

        network_map.hosts =
            parallel_inventory(
                addresses,
                ports,
                timeout_ms,
                collect_banners
            );

        std::cout
            << "============================================================\n"
            << "DISCOVERY RESULTS\n"
            << "============================================================\n";

        for (const HostResult& host : network_map.hosts) {
            print_host(host);
            std::cout << '\n';
        }

        size_t confirmed_hosts = 0;
        size_t open_ports = 0;

        for (const HostResult& host : network_map.hosts) {
            if (host.reachable) {
                ++confirmed_hosts;
            }

            for (const PortResult& port : host.ports) {
                if (port.state == "open") {
                    ++open_ports;
                }
            }
        }

        std::cout
            << "============================================================\n"
            << "STATISTICS\n"
            << "============================================================\n"
            << "Hosts examined : "
            << network_map.hosts.size()
            << '\n'
            << "Hosts confirmed : "
            << confirmed_hosts
            << '\n'
            << "Open TCP ports : "
            << open_ports
            << '\n';

        /*
         * Optional JSON reporting is enabled when a second argument is
         * supplied. The output is deliberately generated from structured
         * records rather than terminal text.
         */
        if (argc >= 3) {
            write_json(
                network_map,
                argv[2]
            );

            std::cout
                << "JSON report: "
                << argv[2]
                << '\n';
        }

        std::cout
            << "\nImportant interpretation rules:\n"
            << "  1. No response does not prove a host is offline.\n"
            << "  2. A closed port still provides evidence that a host responded.\n"
            << "  3. An open port does not conclusively identify an application.\n"
            << "  4. A banner can be missing, misleading, or intentionally generic.\n"
            << "  5. TCP-only discovery does not describe UDP services.\n";

        return 0;
    }
    catch (const std::exception& exception) {
        std::cerr
            << "Fatal error: "
            << exception.what()
            << '\n';

        return 1;
    }
}
