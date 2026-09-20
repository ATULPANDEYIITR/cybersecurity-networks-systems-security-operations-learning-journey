// File: cpp/socket_demo.cpp

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using SocketHandle = SOCKET;
constexpr SocketHandle InvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
constexpr SocketHandle InvalidSocket = -1;
#endif

class SocketRuntime {
public:
    SocketRuntime() {
#ifdef _WIN32
        WSADATA data{};
        const int result = WSAStartup(MAKEWORD(2, 2), &data);
        if (result != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
    }

    ~SocketRuntime() {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    SocketRuntime(const SocketRuntime&) = delete;
    SocketRuntime& operator=(const SocketRuntime&) = delete;
};

void close_socket(SocketHandle socket) {
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

void throw_socket_error(const std::string& operation) {
#ifdef _WIN32
    throw std::system_error(
        WSAGetLastError(),
        std::system_category(),
        operation
    );
#else
    throw std::system_error(errno, std::generic_category(), operation);
#endif
}

SocketHandle create_tcp_socket() {
    const SocketHandle socket_handle =
        socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (socket_handle == InvalidSocket) {
        throw_socket_error("socket");
    }

    return socket_handle;
}

sockaddr_in loopback_address(std::uint16_t port) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    return address;
}

std::uint16_t local_port(SocketHandle socket_handle) {
    sockaddr_in address{};
#ifdef _WIN32
    int length = sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif

    if (getsockname(
            socket_handle,
            reinterpret_cast<sockaddr*>(&address),
            &length) != 0) {
        throw_socket_error("getsockname");
    }

    return ntohs(address.sin_port);
}

void send_all(SocketHandle socket_handle, const std::string& message) {
    std::size_t sent = 0;

    while (sent < message.size()) {
#ifdef _WIN32
        const int result = send(
            socket_handle,
            message.data() + sent,
            static_cast<int>(message.size() - sent),
            0
        );
#else
        const ssize_t result = send(
            socket_handle,
            message.data() + sent,
            message.size() - sent,
            0
        );
#endif

        if (result <= 0) {
            throw_socket_error("send");
        }

        sent += static_cast<std::size_t>(result);
    }
}

std::string receive_message(SocketHandle socket_handle) {
    std::array<char, 256> buffer{};

#ifdef _WIN32
    const int received = recv(
        socket_handle,
        buffer.data(),
        static_cast<int>(buffer.size() - 1),
        0
    );
#else
    const ssize_t received = recv(
        socket_handle,
        buffer.data(),
        buffer.size() - 1,
        0
    );
#endif

    if (received < 0) {
        throw_socket_error("recv");
    }

    return std::string(buffer.data(), static_cast<std::size_t>(received));
}

int main() {
    try {
        SocketRuntime runtime;

        SocketHandle server = create_tcp_socket();

        sockaddr_in server_address = loopback_address(0);

        if (bind(
                server,
                reinterpret_cast<const sockaddr*>(&server_address),
                sizeof(server_address)) != 0) {
            close_socket(server);
            throw_socket_error("bind");
        }

        if (listen(server, 8) != 0) {
            close_socket(server);
            throw_socket_error("listen");
        }

        const std::uint16_t port = local_port(server);

        std::cout << "Server listening on 127.0.0.1:"
                  << port << '\n';

        std::thread client_thread([port]() {
            try {
                SocketHandle client = create_tcp_socket();
                const sockaddr_in destination = loopback_address(port);

                if (connect(
                        client,
                        reinterpret_cast<const sockaddr*>(&destination),
                        sizeof(destination)) != 0) {
                    close_socket(client);
                    throw_socket_error("connect");
                }

                std::cout << "Client local port: "
                          << local_port(client) << '\n';

                send_all(client, "Hello from C++ TCP client");

                close_socket(client);
            } catch (const std::exception& error) {
                std::cerr << "Client error: "
                          << error.what() << '\n';
            }
        });

        sockaddr_in client_address{};
#ifdef _WIN32
        int client_length = sizeof(client_address);
#else
        socklen_t client_length = sizeof(client_address);
#endif

        SocketHandle accepted = accept(
            server,
            reinterpret_cast<sockaddr*>(&client_address),
            &client_length
        );

        if (accepted == InvalidSocket) {
            close_socket(server);
            client_thread.join();
            throw_socket_error("accept");
        }

        const std::string message = receive_message(accepted);

        std::cout << "Server received: "
                  << message << '\n';

        close_socket(accepted);
        close_socket(server);

        client_thread.join();

        std::cout << "Socket lifecycle completed successfully.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: "
                  << error.what() << '\n';
        return 1;
    }
}
