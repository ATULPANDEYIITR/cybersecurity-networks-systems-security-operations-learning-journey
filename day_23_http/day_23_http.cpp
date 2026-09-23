/*
 * HTTP Case Study: Secure Session-Based User API
 *
 * Standard C++17 program.
 *
 * This case study models an HTTP-style API without external networking
 * libraries. The program focuses on the application-layer mechanics:
 *
 *   request parsing
 *   request validation
 *   HTTP methods
 *   status codes
 *   headers
 *   cookies
 *   server-side sessions
 *   authentication
 *   authorization
 *   JSON-like payload handling
 *   caching concepts
 *   rate limiting
 *   logging
 *   error handling
 *   complexity and design trade-offs
 *
 * The program intentionally models the protocol rather than implementing
 * a complete production HTTP/1.1 or HTTP/2 network stack.
 */

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

// ============================================================================
// Utility functions
// ============================================================================

string trim(const string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == string::npos) {
        return "";
    }

    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

string toLower(string value) {
    transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(tolower(character));
        }
    );

    return value;
}

string generateToken(size_t byteCount = 24) {
    static random_device randomDevice;
    static mt19937_64 generator(randomDevice());

    const char* alphabet =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    uniform_int_distribution<size_t> distribution(
        0,
        61
    );

    string token;
    token.reserve(byteCount);

    for (size_t i = 0; i < byteCount; ++i) {
        token.push_back(alphabet[distribution(generator)]);
    }

    return token;
}

string statusReason(int status) {
    static const unordered_map<int, string> reasons{
        {200, "OK"},
        {201, "Created"},
        {202, "Accepted"},
        {204, "No Content"},
        {301, "Moved Permanently"},
        {302, "Found"},
        {303, "See Other"},
        {304, "Not Modified"},
        {307, "Temporary Redirect"},
        {308, "Permanent Redirect"},
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {405, "Method Not Allowed"},
        {409, "Conflict"},
        {413, "Content Too Large"},
        {415, "Unsupported Media Type"},
        {422, "Unprocessable Content"},
        {429, "Too Many Requests"},
        {500, "Internal Server Error"},
        {502, "Bad Gateway"},
        {503, "Service Unavailable"},
        {504, "Gateway Timeout"}
    };

    auto iterator = reasons.find(status);

    if (iterator == reasons.end()) {
        return "Unknown";
    }

    return iterator->second;
}

// ============================================================================
// HTTP data structures
// ============================================================================

struct HttpRequest {
    string method;
    string target;
    string version;
    map<string, string> headers;
    string body;
};

struct HttpResponse {
    int status = 200;
    map<string, string> headers;
    string body;
};

struct User {
    int id;
    string username;
    string displayName;
};

struct Session {
    string sessionId;
    int userId;
    chrono::system_clock::time_point createdAt;
    chrono::system_clock::time_point expiresAt;
};

// ============================================================================
// Header helpers
// ============================================================================

optional<string> getHeader(
    const map<string, string>& headers,
    const string& requestedName
) {
    const string normalizedRequested = toLower(requestedName);

    for (const auto& [name, value] : headers) {
        if (toLower(name) == normalizedRequested) {
            return value;
        }
    }

    return nullopt;
}

void setHeader(
    map<string, string>& headers,
    const string& name,
    const string& value
) {
    headers[name] = value;
}

// ============================================================================
// Cookie parser
// ============================================================================

map<string, string> parseCookies(const string& cookieHeader) {
    map<string, string> cookies;

    stringstream stream(cookieHeader);
    string part;

    while (getline(stream, part, ';')) {
        const auto separator = part.find('=');

        if (separator == string::npos) {
            continue;
        }

        const string name = trim(part.substr(0, separator));
        const string value = trim(part.substr(separator + 1));

        if (!name.empty()) {
            cookies[name] = value;
        }
    }

    return cookies;
}

// ============================================================================
// Session manager
// ============================================================================

class SessionManager {
private:
    unordered_map<string, Session> sessions;
    chrono::seconds lifetime;

public:
    explicit SessionManager(
        chrono::seconds lifetimeSeconds = chrono::seconds(3600)
    )
        : lifetime(lifetimeSeconds) {}

    Session create(int userId) {
        const auto now = chrono::system_clock::now();

        Session session{
            generateToken(32),
            userId,
            now,
            now + lifetime
        };

        sessions[session.sessionId] = session;

        return session;
    }

    optional<Session> get(const string& sessionId) {
        auto iterator = sessions.find(sessionId);

        if (iterator == sessions.end()) {
            return nullopt;
        }

        const auto now = chrono::system_clock::now();

        if (now >= iterator->second.expiresAt) {
            sessions.erase(iterator);
            return nullopt;
        }

        return iterator->second;
    }

    bool revoke(const string& sessionId) {
        return sessions.erase(sessionId) > 0;
    }

    size_t size() const {
        return sessions.size();
    }
};

// ============================================================================
// Sliding-window rate limiter
// ============================================================================

class RateLimiter {
private:
    struct Attempt {
        chrono::steady_clock::time_point timestamp;
    };

    unordered_map<string, vector<Attempt>> attempts;
    size_t maxRequests;
    chrono::seconds window;

public:
    RateLimiter(
        size_t maxRequestsPerWindow,
        chrono::seconds windowDuration
    )
        : maxRequests(maxRequestsPerWindow),
          window(windowDuration) {}

    bool allow(const string& clientKey) {
        const auto now = chrono::steady_clock::now();

        auto& history = attempts[clientKey];

        history.erase(
            remove_if(
                history.begin(),
                history.end(),
                [&](const Attempt& attempt) {
                    return now - attempt.timestamp >= window;
                }
            ),
            history.end()
        );

        if (history.size() >= maxRequests) {
            return false;
        }

        history.push_back({now});
        return true;
    }
};

// ============================================================================
// Request validation
// ============================================================================

struct ValidationResult {
    bool valid;
    int status;
    string message;
};

ValidationResult validateCreateUserRequest(
    const HttpRequest& request
) {
    const auto contentType = getHeader(
        request.headers,
        "Content-Type"
    );

    if (!contentType.has_value()) {
        return {
            false,
            415,
            "Content-Type header is required"
        };
    }

    const string normalizedContentType =
        toLower(contentType->substr(0, contentType->find(';')));

    if (normalizedContentType != "application/json") {
        return {
            false,
            415,
            "Expected application/json"
        };
    }

    const auto contentLength = getHeader(
        request.headers,
        "Content-Length"
    );

    if (contentLength.has_value()) {
        try {
            const auto declaredLength =
                stoull(*contentLength);

            if (declaredLength != request.body.size()) {
                return {
                    false,
                    400,
                    "Content-Length does not match body size"
                };
            }
        } catch (const exception&) {
            return {
                false,
                400,
                "Invalid Content-Length"
            };
        }
    }

    if (request.body.empty()) {
        return {
            false,
            400,
            "Request body is empty"
        };
    }

    if (request.body.find("\"username\"") == string::npos) {
        return {
            false,
            422,
            "Missing username field"
        };
    }

    if (request.body.find("\"displayName\"") == string::npos) {
        return {
            false,
            422,
            "Missing displayName field"
        };
    }

    return {
        true,
        200,
        "Valid request"
    };
}

// ============================================================================
// API server
// ============================================================================

class UserApi {
private:
    unordered_map<int, User> users;
    unordered_map<string, string> userPasswords;
    SessionManager sessions;
    RateLimiter rateLimiter;
    int nextUserId = 1;

    HttpResponse jsonResponse(
        int status,
        const string& json,
        map<string, string> additionalHeaders = {}
    ) const {
        HttpResponse response;

        response.status = status;
        response.body = json;

        response.headers["Content-Type"] =
            "application/json; charset=utf-8";

        response.headers["Content-Length"] =
            to_string(response.body.size());

        response.headers["Cache-Control"] =
            "no-store";

        for (const auto& [name, value] : additionalHeaders) {
            response.headers[name] = value;
        }

        return response;
    }

    optional<int> authenticate(
        const HttpRequest& request
    ) {
        const auto cookieHeader = getHeader(
            request.headers,
            "Cookie"
        );

        if (!cookieHeader.has_value()) {
            return nullopt;
        }

        const auto cookies = parseCookies(*cookieHeader);

        const auto iterator = cookies.find("session_id");

        if (iterator == cookies.end()) {
            return nullopt;
        }

        const auto session = sessions.get(iterator->second);

        if (!session.has_value()) {
            return nullopt;
        }

        return session->userId;
    }

public:
    UserApi()
        : sessions(chrono::seconds(3600)),
          rateLimiter(5, chrono::seconds(60)) {
        users.emplace(
            1,
            User{1, "alice", "Alice Example"}
        );

        userPasswords["alice"] = "correct-password";

        nextUserId = 2;
    }

    HttpResponse handle(
        const HttpRequest& request,
        const string& clientKey
    ) {
        if (!rateLimiter.allow(clientKey)) {
            return jsonResponse(
                429,
                R"({"error":"rate limit exceeded"})",
                {
                    {"Retry-After", "60"}
                }
            );
        }

        if (request.method == "OPTIONS") {
            HttpResponse response;

            response.status = 204;

            response.headers["Allow"] =
                "GET, HEAD, POST, OPTIONS";

            response.headers["Access-Control-Allow-Methods"] =
                "GET, HEAD, POST, OPTIONS";

            response.headers["Access-Control-Allow-Headers"] =
                "Content-Type, Authorization";

            return response;
        }

        if (request.method == "GET" && request.target == "/status") {
            return jsonResponse(
                200,
                R"({"status":"ok","service":"user-api"})"
            );
        }

        if (request.method == "HEAD" && request.target == "/status") {
            HttpResponse response = jsonResponse(
                200,
                R"({"status":"ok"})"
            );

            response.body.clear();
            response.headers["Content-Length"] = "15";

            return response;
        }

        if (
            request.method == "POST" &&
            request.target == "/login"
        ) {
            if (
                request.body.find("\"username\":\"alice\"")
                == string::npos
            ) {
                return jsonResponse(
                    401,
                    R"({"error":"invalid credentials"})"
                );
            }

            if (
                request.body.find("\"password\":\"correct-password\"")
                == string::npos
            ) {
                return jsonResponse(
                    401,
                    R"({"error":"invalid credentials"})"
                );
            }

            const Session session =
                sessions.create(1);

            return jsonResponse(
                200,
                R"({"message":"login successful"})",
                {
                    {
                        "Set-Cookie",
                        "session_id=" + session.sessionId +
                        "; Max-Age=3600; Path=/; HttpOnly; Secure; SameSite=Lax"
                    }
                }
            );
        }

        if (
            request.method == "GET" &&
            request.target == "/protected"
        ) {
            const auto userId = authenticate(request);

            if (!userId.has_value()) {
                return jsonResponse(
                    401,
                    R"({"error":"authentication required"})",
                    {
                        {
                            "WWW-Authenticate",
                            "Bearer realm=\"user-api\""
                        }
                    }
                );
            }

            return jsonResponse(
                200,
                R"({"message":"authenticated resource","userId":1})"
            );
        }

        if (
            request.method == "POST" &&
            request.target == "/users"
        ) {
            const validation =
                validateCreateUserRequest(request);

            if (!validation.valid) {
                return jsonResponse(
                    validation.status,
                    "{\"error\":\"" +
                    validation.message +
                    "\"}"
                );
            }

            if (request.body.size() > 1'000'000) {
                return jsonResponse(
                    413,
                    R"({"error":"request body too large"})"
                );
            }

            const int userId = nextUserId++;

            User user{
                userId,
                "generated-user-" + to_string(userId),
                "Generated User"
            };

            users[userId] = user;

            return jsonResponse(
                201,
                "{\"id\":" +
                to_string(user.id) +
                ",\"username\":\"" +
                user.username +
                "\",\"displayName\":\"" +
                user.displayName +
                "\"}",
                {
                    {
                        "Location",
                        "/users/" + to_string(user.id)
                    }
                }
            );
        }

        if (
            request.method == "GET" &&
            request.target.rfind("/users/", 0) == 0
        ) {
            const string idPart =
                request.target.substr(7);

            try {
                const int id = stoi(idPart);

                auto iterator = users.find(id);

                if (iterator == users.end()) {
                    return jsonResponse(
                        404,
                        R"({"error":"user not found"})"
                    );
                }

                const User& user = iterator->second;

                return jsonResponse(
                    200,
                    "{\"id\":" +
                    to_string(user.id) +
                    ",\"username\":\"" +
                    user.username +
                    "\",\"displayName\":\"" +
                    user.displayName +
                    "\"}"
                );
            } catch (const exception&) {
                return jsonResponse(
                    400,
                    R"({"error":"invalid user ID"})"
                );
            }
        }

        return jsonResponse(
            404,
            R"({"error":"resource not found"})"
        );
    }
};

// ============================================================================
// HTTP request parser
// ============================================================================

HttpRequest parseHttpRequest(const string& rawRequest) {
    HttpRequest request;

    const auto headerEnd =
        rawRequest.find("\r\n\r\n");

    if (headerEnd == string::npos) {
        throw runtime_error(
            "HTTP request has no header/body separator"
        );
    }

    const string headerPart =
        rawRequest.substr(0, headerEnd);

    request.body =
        rawRequest.substr(headerEnd + 4);

    stringstream lines(headerPart);
    string requestLine;

    if (!getline(lines, requestLine)) {
        throw runtime_error(
            "Missing HTTP request line"
        );
    }

    requestLine = trim(requestLine);

    stringstream requestLineStream(requestLine);

    if (
        !(requestLineStream
            >> request.method
            >> request.target
            >> request.version)
    ) {
        throw runtime_error(
            "Malformed HTTP request line"
        );
    }

    string line;

    while (getline(lines, line)) {
        line = trim(line);

        if (line.empty()) {
            continue;
        }

        const auto separator = line.find(':');

        if (separator == string::npos) {
            throw runtime_error(
                "Malformed HTTP header"
            );
        }

        const string name =
            trim(line.substr(0, separator));

        const string value =
            trim(line.substr(separator + 1));

        request.headers[name] = value;
    }

    return request;
}

// ============================================================================
// HTTP response serializer
// ============================================================================

string serializeResponse(
    const HttpResponse& response
) {
    ostringstream output;

    output
        << "HTTP/1.1 "
        << response.status
        << " "
        << statusReason(response.status)
        << "\r\n";

    for (const auto& [name, value] : response.headers) {
        output
            << name
            << ": "
            << value
            << "\r\n";
    }

    output << "\r\n";
    output << response.body;

    return output.str();
}

// ============================================================================
// Case study demonstration
// ============================================================================

void printResponse(const HttpResponse& response) {
    cout
        << "HTTP/1.1 "
        << response.status
        << " "
        << statusReason(response.status)
        << "\n";

    for (const auto& [name, value] : response.headers) {
        cout
            << name
            << ": "
            << value
            << "\n";
    }

    cout << "\n";

    if (!response.body.empty()) {
        cout << response.body << "\n";
    }
}

void demonstrateRequestParsing() {
    cout << "\n";
    cout << "============================================================\n";
    cout << "HTTP request parser\n";
    cout << "============================================================\n";

    const string rawRequest =
        "POST /users HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 43\r\n"
        "\r\n"
        "{\"username\":\"bob\",\"displayName\":\"Bob\"}";

    try {
        const HttpRequest request =
            parseHttpRequest(rawRequest);

        cout << "Method: " << request.method << "\n";
        cout << "Target: " << request.target << "\n";
        cout << "Version: " << request.version << "\n";

        for (const auto& [name, value] : request.headers) {
            cout << name << ": " << value << "\n";
        }

        cout << "Body: " << request.body << "\n";
    } catch (const exception& error) {
        cout
            << "Parsing error: "
            << error.what()
            << "\n";
    }
}

void demonstrateApi() {
    cout << "\n";
    cout << "============================================================\n";
    cout << "User API case study\n";
    cout << "============================================================\n";

    UserApi api;

    HttpRequest statusRequest{
        "GET",
        "/status",
        "HTTP/1.1",
        {
            {"Host", "localhost:8080"},
            {"Accept", "application/json"}
        },
        ""
    };

    cout << "\nGET /status\n";
    printResponse(
        api.handle(statusRequest, "127.0.0.1")
    );

    HttpRequest loginRequest{
        "POST",
        "/login",
        "HTTP/1.1",
        {
            {"Host", "localhost:8080"},
            {"Content-Type", "application/json"},
            {"Content-Length", "53"}
        },
        R"({"username":"alice","password":"correct-password"})"
    };

    cout << "\nPOST /login\n";
    const HttpResponse loginResponse =
        api.handle(loginRequest, "127.0.0.1");

    printResponse(loginResponse);

    string sessionId;

    const auto cookieHeader =
        getHeader(
            loginResponse.headers,
            "Set-Cookie"
        );

    if (cookieHeader.has_value()) {
        const auto separator =
            cookieHeader->find('=');

        const auto end =
            cookieHeader->find(';');

        if (
            separator != string::npos &&
            end != string::npos
        ) {
            sessionId =
                cookieHeader->substr(
                    separator + 1,
                    end - separator - 1
                );
        }
    }

    HttpRequest protectedRequest{
        "GET",
        "/protected",
        "HTTP/1.1",
        {
            {"Host", "localhost:8080"},
            {
                "Cookie",
                "session_id=" + sessionId
            }
        },
        ""
    };

    cout << "\nGET /protected\n";
    printResponse(
        api.handle(
            protectedRequest,
            "127.0.0.1"
        )
    );

    HttpRequest createRequest{
        "POST",
        "/users",
        "HTTP/1.1",
        {
            {"Host", "localhost:8080"},
            {"Content-Type", "application/json"},
            {"Content-Length", "49"}
        },
        R"({"username":"charlie","displayName":"Charlie"})"
    };

    cout << "\nPOST /users\n";
    printResponse(
        api.handle(
            createRequest,
            "127.0.0.1"
        )
    );

    HttpRequest missingRequest{
        "GET",
        "/users/9999",
        "HTTP/1.1",
        {
            {"Host", "localhost:8080"}
        },
        ""
    };

    cout << "\nGET /users/9999\n";
    printResponse(
        api.handle(
            missingRequest,
            "127.0.0.1"
        )
    );
}

void demonstrateFailureConditions() {
    cout << "\n";
    cout << "============================================================\n";
    cout << "Failure conditions\n";
    cout << "============================================================\n";

    UserApi api;

    HttpRequest invalidContentType{
        "POST",
        "/users",
        "HTTP/1.1",
        {
            {"Content-Type", "text/plain"},
            {"Content-Length", "10"}
        },
        "bad input!"
    };

    cout << "\nWrong Content-Type:\n";
    printResponse(
        api.handle(
            invalidContentType,
            "client-A"
        )
    );

    HttpRequest malformedLength{
        "POST",
        "/users",
        "HTTP/1.1",
        {
            {"Content-Type", "application/json"},
            {"Content-Length", "999"}
        },
        R"({"username":"x","displayName":"X"})"
    };

    cout << "\nIncorrect Content-Length:\n";
    printResponse(
        api.handle(
            malformedLength,
            "client-A"
        )
    );

    HttpRequest unauthenticated{
        "GET",
        "/protected",
        "HTTP/1.1",
        {
            {"Host", "localhost"}
        },
        ""
    };

    cout << "\nMissing session:\n";
    printResponse(
        api.handle(
            unauthenticated,
            "client-B"
        )
    );
}

void demonstrateComplexity() {
    cout << "\n";
    cout << "============================================================\n";
    cout << "Complexity and trade-offs\n";
    cout << "============================================================\n";

    cout << "unordered_map session lookup: average O(1).\n";
    cout << "unordered_map user lookup: average O(1).\n";
    cout << "Cookie parsing: O(number of cookie characters).\n";
    cout << "Request parsing: O(request size).\n";
    cout << "Rate-limit cleanup: depends on stored client history.\n";

    cout << "\nTrade-offs:\n";
    cout << "- In-memory sessions are fast but disappear when the process stops.\n";
    cout << "- Distributed deployments need shared or externally stored session state.\n";
    cout << "- Stateless tokens reduce server-side session storage but require careful token lifecycle design.\n";
    cout << "- Aggressive retries can increase load during an outage.\n";
    cout << "- Caching improves performance but can serve stale data when configured incorrectly.\n";
    cout << "- Detailed logs improve diagnosis but must not expose secrets.\n";
}

int main() {
    cout << "HTTP APPLICATION-LAYER CASE STUDY\n";
    cout << "Modern C++17\n";

    demonstrateRequestParsing();
    demonstrateApi();
    demonstrateFailureConditions();
    demonstrateComplexity();

    cout << "\n";
    cout << "============================================================\n";
    cout << "HTTP concepts demonstrated\n";
    cout << "============================================================\n";

    cout << "Requests -> method, target, version, headers, body\n";
    cout << "Responses -> status, headers, body\n";
    cout << "Methods -> GET, POST, PUT/PATCH concepts, DELETE, HEAD, OPTIONS\n";
    cout << "Status -> success, redirection, client error, server error\n";
    cout << "Headers -> metadata and protocol/application controls\n";
    cout << "Cookies -> client-held state\n";
    cout << "Sessions -> server-side state referenced by a cookie\n";
    cout << "Security -> validation, session protection, rate limiting\n";
    cout << "Operations -> logging, failures, limits, complexity\n";

    return 0;
}
