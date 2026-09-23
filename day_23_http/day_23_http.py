"""
HTTP: Requests, Responses, Methods, Status Codes, Headers, Cookies, Sessions,
Browser DevTools, and curl

A self-contained study program covering HTTP from beginner to advanced concepts.
The examples use only Python's standard library.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import json
import secrets
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Dict, List, Optional, Tuple


# ============================================================================
# 1. HTTP FUNDAMENTALS
# ============================================================================

def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_http_message() -> None:
    print_section("1. HTTP message structure")

    request = (
        "GET /products?page=2 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept: application/json\r\n"
        "User-Agent: StudyClient/1.0\r\n"
        "Cookie: session_id=abc123\r\n"
        "\r\n"
    )

    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 17\r\n"
        "\r\n"
        '{"items": [1, 2]}'
    )

    print("Example HTTP request:")
    print(request.replace("\r\n", "\\r\\n\n"))

    print("Example HTTP response:")
    print(response.replace("\r\n", "\\r\\n\n"))

    print("An HTTP request normally contains:")
    print("  method + target + HTTP version")
    print("  request headers")
    print("  optional request body")

    print("An HTTP response normally contains:")
    print("  HTTP version + status code + reason phrase")
    print("  response headers")
    print("  optional response body")


# ============================================================================
# 2. URL STRUCTURE
# ============================================================================

def demonstrate_urls() -> None:
    print_section("2. URL structure")

    url = (
        "https://api.example.com:443/users/profile"
        "?page=2&active=true#security"
    )

    parsed = urllib.parse.urlparse(url)

    print("URL:", url)
    print("Scheme:", parsed.scheme)
    print("Hostname:", parsed.hostname)
    print("Port:", parsed.port)
    print("Path:", parsed.path)
    print("Query:", parsed.query)
    print("Fragment:", parsed.fragment)

    query_parameters = urllib.parse.parse_qs(parsed.query)
    print("Decoded query parameters:", query_parameters)

    rebuilt = urllib.parse.urlunparse(parsed)
    print("Rebuilt URL:", rebuilt)

    print(
        "\nFragments are handled by the client and are normally not sent "
        "to the HTTP server."
    )


# ============================================================================
# 3. HTTP METHODS
# ============================================================================

@dataclass
class Resource:
    resource_id: int
    name: str
    description: str


class InMemoryResourceAPI:
    """
    A small resource model used to demonstrate HTTP method semantics.

    HTTP methods describe the intended operation. They do not automatically
    make an operation safe or idempotent; the server implementation matters.
    """

    def __init__(self) -> None:
        self.resources: Dict[int, Resource] = {}
        self.next_id = 1

    def get(self, resource_id: Optional[int] = None):
        if resource_id is None:
            return list(self.resources.values())
        return self.resources.get(resource_id)

    def post(self, name: str, description: str) -> Resource:
        resource = Resource(self.next_id, name, description)
        self.resources[self.next_id] = resource
        self.next_id += 1
        return resource

    def put(self, resource_id: int, name: str, description: str) -> Optional[Resource]:
        if resource_id not in self.resources:
            return None
        resource = Resource(resource_id, name, description)
        self.resources[resource_id] = resource
        return resource

    def patch(
        self,
        resource_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Optional[Resource]:
        resource = self.resources.get(resource_id)
        if resource is None:
            return None

        if name is not None:
            resource.name = name
        if description is not None:
            resource.description = description

        return resource

    def delete(self, resource_id: int) -> bool:
        return self.resources.pop(resource_id, None) is not None


def demonstrate_methods() -> None:
    print_section("3. HTTP methods")

    api = InMemoryResourceAPI()

    created = api.post("HTTP", "Protocol for application communication")
    print("POST created:", created)

    print("GET collection:", api.get())

    replaced = api.put(
        created.resource_id,
        "HTTP/1.1",
        "Request-response application protocol",
    )
    print("PUT replaced:", replaced)

    patched = api.patch(created.resource_id, name="HTTP/1.1 + HTTP/2 concepts")
    print("PATCH partially updated:", patched)

    deleted = api.delete(created.resource_id)
    print("DELETE successful:", deleted)

    methods = {
        "GET": "Retrieve a representation",
        "POST": "Submit data or request processing/creation",
        "PUT": "Replace a resource representation",
        "PATCH": "Partially modify a resource",
        "DELETE": "Request resource deletion",
        "HEAD": "Like GET, but normally without a response body",
        "OPTIONS": "Discover communication options",
        "TRACE": "Diagnostic method; often disabled for security reasons",
        "CONNECT": "Establish a tunnel, commonly for HTTPS through a proxy",
    }

    for method, purpose in methods.items():
        print(f"{method:8} -> {purpose}")

    print(
        "\nSafe methods generally do not intend to change server state. "
        "GET and HEAD are examples."
    )
    print(
        "Idempotent means repeating the same request has the same intended "
        "effect as making it once. PUT and DELETE are defined as idempotent."
    )
    print(
        "POST is generally not idempotent: sending it twice may create two "
        "resources or perform an operation twice."
    )


# ============================================================================
# 4. STATUS CODES
# ============================================================================

def demonstrate_status_codes() -> None:
    print_section("4. HTTP status codes")

    categories = {
        "1xx": "Informational",
        "2xx": "Successful",
        "3xx": "Redirection",
        "4xx": "Client error",
        "5xx": "Server error",
    }

    for category, meaning in categories.items():
        print(category, "->", meaning)

    important_codes = [
        200, 201, 202, 204,
        301, 302, 304, 307, 308,
        400, 401, 403, 404, 405, 409, 415, 422, 429,
        500, 501, 502, 503, 504,
    ]

    for code in important_codes:
        status = HTTPStatus(code)
        print(f"{code}: {status.phrase}")

    print(
        "\n401 normally means authentication is required or credentials are "
        "invalid. 403 means the server understood the request but refuses "
        "authorization."
    )
    print(
        "404 indicates that the requested resource was not found, although "
        "servers may intentionally hide resource existence."
    )
    print(
        "429 indicates rate limiting. A Retry-After header may tell the client "
        "when to try again."
    )


# ============================================================================
# 5. HEADERS
# ============================================================================

def demonstrate_headers() -> None:
    print_section("5. HTTP headers")

    headers = {
        "Host": "example.com",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Content-Length": "48",
        "Authorization": "Bearer example-token",
        "Cache-Control": "no-cache",
        "User-Agent": "StudyClient/1.0",
    }

    for name, value in headers.items():
        print(f"{name}: {value}")

    print("\nCommon request headers:")
    print("  Accept")
    print("  Authorization")
    print("  Content-Type")
    print("  Content-Length")
    print("  Cookie")
    print("  User-Agent")
    print("  Origin")
    print("  Referer")

    print("\nCommon response headers:")
    print("  Content-Type")
    print("  Content-Length")
    print("  Set-Cookie")
    print("  Cache-Control")
    print("  Location")
    print("  ETag")
    print("  Last-Modified")
    print("  Retry-After")
    print("  Content-Encoding")

    print(
        "\nContent-Type describes the media type of the representation, while "
        "Accept describes media types the client can receive."
    )


# ============================================================================
# 6. JSON REQUEST/RESPONSE
# ============================================================================

def demonstrate_json() -> None:
    print_section("6. JSON request and response bodies")

    payload = {
        "name": "Ada",
        "role": "engineer",
        "active": True,
        "skills": ["Python", "HTTP"],
    }

    encoded = json.dumps(payload).encode("utf-8")
    print("Python object:", payload)
    print("JSON bytes:", encoded)

    decoded = json.loads(encoded.decode("utf-8"))
    print("Decoded object:", decoded)

    print(
        "\nA JSON API commonly uses Content-Type: application/json. "
        "JSON is data format, while HTTP is the transport/application protocol."
    )


# ============================================================================
# 7. COOKIES
# ============================================================================

@dataclass
class Cookie:
    name: str
    value: str
    secure: bool = False
    http_only: bool = False
    same_site: str = "Lax"
    max_age: Optional[int] = None


class CookieJar:
    def __init__(self) -> None:
        self.cookies: Dict[str, Cookie] = {}

    def receive_set_cookie(self, cookie: Cookie) -> None:
        self.cookies[cookie.name] = cookie

    def cookie_header(self) -> str:
        return "; ".join(
            f"{cookie.name}={cookie.value}"
            for cookie in self.cookies.values()
        )


def demonstrate_cookies() -> None:
    print_section("7. Cookies")

    jar = CookieJar()

    session_cookie = Cookie(
        name="session_id",
        value=secrets.token_urlsafe(24),
        secure=True,
        http_only=True,
        same_site="Lax",
        max_age=3600,
    )

    jar.receive_set_cookie(session_cookie)

    print("Stored cookie:", session_cookie)
    print("Cookie request header:", jar.cookie_header())

    print("\nImportant cookie attributes:")
    print("  Secure   -> send over HTTPS")
    print("  HttpOnly -> JavaScript cannot normally read the cookie")
    print("  SameSite -> controls cross-site cookie sending behavior")
    print("  Max-Age  -> lifetime in seconds")
    print("  Domain   -> controls applicable host scope")
    print("  Path     -> controls applicable URL path scope")

    print(
        "\nCookies are client-side state. A cookie can contain a session "
        "identifier rather than the complete session data."
    )


# ============================================================================
# 8. SESSIONS
# ============================================================================

@dataclass
class Session:
    session_id: str
    user_id: str
    created_at: float
    expires_at: float


class SessionStore:
    def __init__(self, lifetime_seconds: int = 3600) -> None:
        self.lifetime_seconds = lifetime_seconds
        self.sessions: Dict[str, Session] = {}

    def create(self, user_id: str) -> Session:
        session_id = secrets.token_urlsafe(32)
        now = time.time()

        session = Session(
            session_id=session_id,
            user_id=user_id,
            created_at=now,
            expires_at=now + self.lifetime_seconds,
        )

        self.sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Optional[Session]:
        session = self.sessions.get(session_id)

        if session is None:
            return None

        if time.time() >= session.expires_at:
            del self.sessions[session_id]
            return None

        return session

    def revoke(self, session_id: str) -> bool:
        return self.sessions.pop(session_id, None) is not None


def demonstrate_sessions() -> None:
    print_section("8. Sessions")

    store = SessionStore(lifetime_seconds=300)

    session = store.create("user-42")

    print("Created session:", session.session_id)
    print("Session lookup:", store.get(session.session_id))

    print("Session cookie value:", session.session_id)

    revoked = store.revoke(session.session_id)
    print("Session revoked:", revoked)
    print("Lookup after revocation:", store.get(session.session_id))

    print(
        "\nA common design is: browser stores a random session ID in a cookie; "
        "server stores the authenticated state associated with that ID."
    )


# ============================================================================
# 9. AUTHENTICATION AND AUTHORIZATION
# ============================================================================

def demonstrate_authentication_headers() -> None:
    print_section("9. Authentication and authorization")

    username = "alice"
    password = "example-password"

    basic_value = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")

    print("Basic Authorization header:")
    print(f"Authorization: Basic {basic_value}")

    print("\nBearer-token example:")
    print("Authorization: Bearer eyJhbGciOi...")

    print(
        "\nBasic authentication is an encoding mechanism, not encryption. "
        "HTTPS is required to protect credentials in transit."
    )
    print(
        "Bearer tokens must be protected because possession of the token can "
        "grant access."
    )


# ============================================================================
# 10. REQUEST VALIDATION
# ============================================================================

def validate_json_request(
    body: bytes,
    content_type: str,
    content_length: Optional[str],
) -> Tuple[bool, str]:
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError:
            return False, "Invalid Content-Length"

        if declared_length != len(body):
            return False, "Content-Length does not match body length"

    media_type = content_type.split(";", 1)[0].strip().lower()

    if media_type != "application/json":
        return False, "Expected application/json"

    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False, "Malformed JSON"

    if not isinstance(data, dict):
        return False, "JSON body must be an object"

    if "name" not in data:
        return False, "Missing required field: name"

    if not isinstance(data["name"], str) or not data["name"].strip():
        return False, "name must be a non-empty string"

    return True, "Valid request"


# ============================================================================
# 11. LOCAL HTTP SERVER
# ============================================================================

class StudyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "HTTPStudyServer/1.0"

    def _send_json(
        self,
        status: int,
        payload: dict,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")

        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)

        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/":
            self._send_json(
                200,
                {
                    "message": "HTTP study server",
                    "method": self.command,
                    "path": parsed.path,
                    "query": urllib.parse.parse_qs(parsed.query),
                },
            )
            return

        if parsed.path == "/status":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "server_time": time.time(),
                },
            )
            return

        if parsed.path == "/protected":
            cookie_header = self.headers.get("Cookie", "")

            if "session_id=" not in cookie_header:
                self._send_json(
                    401,
                    {"error": "Authentication required"},
                    {"WWW-Authenticate": 'Bearer realm="study-api"'},
                )
                return

            self._send_json(
                200,
                {"message": "Protected resource accessed"},
            )
            return

        self._send_json(
            404,
            {"error": "Resource not found", "path": parsed.path},
        )

    def do_HEAD(self) -> None:
        body = b'{"status":"ok"}'

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def do_POST(self) -> None:
        if self.path != "/users":
            self._send_json(404, {"error": "Resource not found"})
            return

        content_length = self.headers.get("Content-Length")
        if content_length is None:
            self._send_json(411, {"error": "Content-Length required"})
            return

        try:
            length = int(content_length)
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length"})
            return

        if length > 1_000_000:
            self._send_json(413, {"error": "Request body too large"})
            return

        body = self.rfile.read(length)

        valid, message = validate_json_request(
            body,
            self.headers.get("Content-Type", ""),
            content_length,
        )

        if not valid:
            self._send_json(400, {"error": message})
            return

        data = json.loads(body.decode("utf-8"))

        self._send_json(
            201,
            {
                "id": 1001,
                "user": data,
            },
            {"Location": "/users/1001"},
        )

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def log_message(self, format_string: str, *args) -> None:
        print("[SERVER]", format_string % args)


def start_local_server() -> Tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0),
        StudyHTTPRequestHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    return server, thread


# ============================================================================
# 12. HTTP CLIENT
# ============================================================================

def http_request(
    host: str,
    port: int,
    method: str,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=5)

    request_headers = headers or {}

    if body is not None and "Content-Length" not in request_headers:
        request_headers["Content-Length"] = str(len(body))

    connection.request(
        method,
        path,
        body=body,
        headers=request_headers,
    )

    response = connection.getresponse()

    response_body = response.read()

    response_headers = {
        key: value
        for key, value in response.getheaders()
    }

    status = response.status

    connection.close()

    return status, response_headers, response_body


def demonstrate_client() -> None:
    print_section("12. HTTP client against a local server")

    server, _ = start_local_server()
    port = server.server_port

    try:
        status, headers, body = http_request(
            "127.0.0.1",
            port,
            "GET",
            "/status",
            headers={"Accept": "application/json"},
        )

        print("GET /status")
        print("Status:", status)
        print("Content-Type:", headers.get("Content-Type"))
        print("Body:", body.decode("utf-8"))

        payload = json.dumps(
            {
                "name": "Ada",
                "role": "engineer",
            }
        ).encode("utf-8")

        status, headers, body = http_request(
            "127.0.0.1",
            port,
            "POST",
            "/users",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body=payload,
        )

        print("\nPOST /users")
        print("Status:", status)
        print("Location:", headers.get("Location"))
        print("Body:", body.decode("utf-8"))

        status, headers, body = http_request(
            "127.0.0.1",
            port,
            "GET",
            "/missing",
        )

        print("\nGET /missing")
        print("Status:", status)
        print("Body:", body.decode("utf-8"))

    finally:
        server.shutdown()
        server.server_close()


# ============================================================================
# 13. REDIRECTION
# ============================================================================

def demonstrate_redirect_logic() -> None:
    print_section("13. Redirects")

    redirect_codes = {
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        307: "Temporary Redirect",
        308: "Permanent Redirect",
    }

    for code, meaning in redirect_codes.items():
        print(f"{code}: {meaning}")

    print(
        "\n307 and 308 preserve the HTTP method when following a redirect. "
        "303 tells the client to retrieve the target using GET."
    )


# ============================================================================
# 14. CACHING
# ============================================================================

def demonstrate_caching() -> None:
    print_section("14. HTTP caching")

    cache_headers = {
        "Cache-Control": "public, max-age=3600",
        "ETag": '"resource-version-7"',
        "Last-Modified": "Wed, 23 Sep 2026 05:00:00 GMT",
    }

    for name, value in cache_headers.items():
        print(f"{name}: {value}")

    print(
        "\nA client can later send If-None-Match with the ETag. "
        "If the representation has not changed, the server can return 304."
    )

    print(
        "Conditional requests reduce unnecessary transfer and can improve "
        "latency and bandwidth usage."
    )


# ============================================================================
# 15. CONTENT NEGOTIATION AND ENCODING
# ============================================================================

def demonstrate_content_negotiation() -> None:
    print_section("15. Content negotiation")

    print("Accept: application/json, text/plain;q=0.8")
    print("Accept-Encoding: gzip, br")
    print("Accept-Language: en-IN,en;q=0.9")

    print(
        "\nThe server can select a representation based on client preferences. "
        "Quality values such as q=0.8 influence preference but do not represent "
        "HTTP status or application correctness."
    )


# ============================================================================
# 16. HTTP/1.1 CONNECTION BEHAVIOR
# ============================================================================

def demonstrate_connection_behavior() -> None:
    print_section("16. Connections and HTTP versions")

    print("HTTP/1.0: historically used shorter-lived connections by default.")
    print("HTTP/1.1: persistent connections became standard behavior.")
    print("HTTP/2: multiplexes streams over a connection and uses binary framing.")
    print("HTTP/3: uses QUIC over UDP and provides HTTP semantics through QUIC streams.")

    print(
        "\nHTTP version affects transport and framing behavior. The basic "
        "request-response concepts remain recognizable across versions."
    )


# ============================================================================
# 17. TIMEOUTS, RETRIES, AND RESILIENCE
# ============================================================================

def retry_delay(attempt: int, base: float = 0.25, maximum: float = 8.0) -> float:
    exponential = min(maximum, base * (2 ** attempt))
    jitter = secrets.randbelow(1000) / 1000.0 * base
    return min(maximum, exponential + jitter)


def demonstrate_resilience() -> None:
    print_section("17. Timeouts, retries, and resilience")

    for attempt in range(5):
        print(
            f"attempt={attempt}, suggested_delay={retry_delay(attempt):.3f}s"
        )

    print(
        "\nClients should use finite connection/read timeouts. Retrying every "
        "failure blindly can amplify outages."
    )
    print(
        "Retries are usually more appropriate for transient failures such as "
        "some 502, 503, or 504 responses. Application semantics must be "
        "considered before retrying non-idempotent operations."
    )


# ============================================================================
# 18. SECURITY
# ============================================================================

def demonstrate_security() -> None:
    print_section("18. HTTP security considerations")

    print("1. Use HTTPS for sensitive traffic.")
    print("2. Validate all untrusted input.")
    print("3. Do not place passwords or secrets in URLs.")
    print("4. Protect session identifiers.")
    print("5. Use Secure and HttpOnly where appropriate for session cookies.")
    print("6. Configure SameSite deliberately.")
    print("7. Use CSRF protection where cookie authentication requires it.")
    print("8. Avoid logging authorization headers and session cookies.")
    print("9. Enforce request-size limits.")
    print("10. Apply rate limits to sensitive endpoints.")
    print("11. Validate Content-Type and payload structure.")
    print("12. Do not trust client-controlled headers.")

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()

    print("\nExample random session token:", token)
    print("SHA-256 representation for comparison:", digest)

    print(
        "\nA cryptographic hash is not a substitute for a secure random token. "
        "secrets.token_urlsafe() is used here because session identifiers need "
        "unpredictability."
    )


# ============================================================================
# 19. ERROR CLASSIFICATION
# ============================================================================

def classify_status(status_code: int) -> str:
    if 100 <= status_code <= 199:
        return "informational"
    if 200 <= status_code <= 299:
        return "success"
    if 300 <= status_code <= 399:
        return "redirection"
    if 400 <= status_code <= 499:
        return "client-side/request problem"
    if 500 <= status_code <= 599:
        return "server-side problem"
    return "invalid HTTP status code"


def demonstrate_error_classification() -> None:
    print_section("19. Error classification")

    for code in [200, 201, 301, 304, 400, 401, 403, 404, 409, 429, 500, 502, 503, 504]:
        print(code, "->", classify_status(code))


# ============================================================================
# 20. OBSERVABILITY
# ============================================================================

@dataclass
class RequestLog:
    method: str
    path: str
    status: int
    duration_ms: float
    request_id: str


def demonstrate_observability() -> None:
    print_section("20. HTTP observability")

    log = RequestLog(
        method="GET",
        path="/api/users",
        status=200,
        duration_ms=12.7,
        request_id=secrets.token_hex(16),
    )

    print(log)

    print(
        "\nUseful production measurements include request rate, status-code "
        "distribution, latency, timeout counts, response sizes, and correlation "
        "or request IDs."
    )


# ============================================================================
# 21. EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    print_section("21. Important edge cases")

    cases = [
        ("Empty body", b""),
        ("Whitespace body", b"   "),
        ("Malformed UTF-8", b"\xff\xfe\xfd"),
        ("Malformed JSON", b'{"name":'),
        ("Wrong JSON type", b'["not", "object"]'),
        ("Valid JSON", b'{"name":"Ada"}'),
    ]

    for description, body in cases:
        valid, message = validate_json_request(
            body,
            "application/json",
            str(len(body)),
        )
        print(f"{description:20} -> valid={valid}, message={message}")

    print(
        "\nApplications should distinguish malformed transport data, malformed "
        "syntax, semantically invalid data, authentication failures, and "
        "authorization failures."
    )


# ============================================================================
# 22. BROWSER DEVTOOLS STUDY GUIDE
# ============================================================================

def demonstrate_devtools_workflow() -> None:
    print_section("22. Browser DevTools workflow")

    workflow = [
        "Open Developer Tools.",
        "Open the Network panel.",
        "Reload the page.",
        "Select a request.",
        "Inspect Request URL and method.",
        "Inspect request headers.",
        "Inspect request payload.",
        "Inspect cookies.",
        "Inspect response status.",
        "Inspect response headers.",
        "Inspect response body or preview.",
        "Check timing information.",
        "Compare failed and successful requests.",
    ]

    for step_number, step in enumerate(workflow, start=1):
        print(f"{step_number:2}. {step}")

    print(
        "\nThe Network panel is useful because it exposes the actual HTTP "
        "traffic generated by browser actions rather than only showing "
        "application-level UI behavior."
    )


# ============================================================================
# 23. CURL STUDY COMMANDS
# ============================================================================

def demonstrate_curl_commands() -> None:
    print_section("23. curl command examples")

    commands = [
        "curl https://example.com",
        "curl -i https://example.com",
        "curl -I https://example.com",
        "curl -v https://example.com",
        "curl -X POST https://example.com/users",
        "curl -H 'Accept: application/json' https://example.com/users",
        "curl -H 'Content-Type: application/json' -d '{\"name\":\"Ada\"}' https://example.com/users",
        "curl -b 'session_id=abc123' https://example.com/protected",
        "curl -c cookies.txt -b cookies.txt https://example.com/",
        "curl -L https://example.com/redirect",
    ]

    for command in commands:
        print("$", command)

    print(
        "\n-i includes response headers. -I requests headers without the normal "
        "response body. -v displays detailed connection and protocol information. "
        "-L follows redirects. -H adds a header. -d sends request data. "
        "-b sends cookies and -c stores cookies."
    )


# ============================================================================
# 24. COMPLETE MINI TRANSACTION
# ============================================================================

def complete_transaction_demo() -> None:
    print_section("24. Complete HTTP transaction")

    server, _ = start_local_server()
    port = server.server_port

    try:
        request_body = json.dumps(
            {
                "name": "Grace",
                "role": "systems engineer",
            }
        ).encode("utf-8")

        print("Client constructs:")
        print("POST /users HTTP/1.1")
        print(f"Host: 127.0.0.1:{port}")
        print("Accept: application/json")
        print("Content-Type: application/json")
        print(f"Content-Length: {len(request_body)}")
        print()
        print(request_body.decode())

        status, headers, body = http_request(
            "127.0.0.1",
            port,
            "POST",
            "/users",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body=request_body,
        )

        print("\nServer responds:")
        print(f"HTTP/1.1 {status} {HTTPStatus(status).phrase}")

        for name, value in headers.items():
            print(f"{name}: {value}")

        print()
        print(body.decode())

    finally:
        server.shutdown()
        server.server_close()


# ============================================================================
# 25. MAIN
# ============================================================================

def main() -> None:
    print_section("HTTP COMPREHENSIVE STUDY PROGRAM")
    print(
        "This program demonstrates HTTP messages, methods, status codes, "
        "headers, cookies, sessions, APIs, caching, security, local servers, "
        "clients, DevTools concepts, and curl workflows."
    )

    explain_http_message()
    demonstrate_urls()
    demonstrate_methods()
    demonstrate_status_codes()
    demonstrate_headers()
    demonstrate_json()
    demonstrate_cookies()
    demonstrate_sessions()
    demonstrate_authentication_headers()
    demonstrate_client()
    demonstrate_redirect_logic()
    demonstrate_caching()
    demonstrate_content_negotiation()
    demonstrate_connection_behavior()
    demonstrate_resilience()
    demonstrate_security()
    demonstrate_error_classification()
    demonstrate_observability()
    demonstrate_edge_cases()
    demonstrate_devtools_workflow()
    demonstrate_curl_commands()
    complete_transaction_demo()

    print_section("Study program completed")
    print(
        "The local server and client examples completed without requiring "
        "external packages."
    )


if __name__ == "__main__":
    main()
