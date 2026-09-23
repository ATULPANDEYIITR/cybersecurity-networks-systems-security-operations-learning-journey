/*
 * HTTP: Requests, Responses, Methods, Status Codes, Headers, Cookies,
 * Sessions, Browser DevTools, and curl
 *
 * This file uses standard JavaScript and Node.js built-in APIs.
 * It demonstrates HTTP concepts from basic requests to a complete local API.
 */

"use strict";

const http = require("http");
const crypto = require("crypto");
const { URL } = require("url");

// ============================================================================
// 1. BASIC HTTP MESSAGE MODEL
// ============================================================================

function printSection(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function demonstrateHttpMessages() {
    printSection("1. HTTP request and response structure");

    const request = [
        "GET /users?page=2 HTTP/1.1",
        "Host: example.com",
        "Accept: application/json",
        "User-Agent: HttpStudyClient/1.0",
        "",
        ""
    ].join("\r\n");

    const response = [
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "Content-Length: 17",
        "",
        '{"items":[1,2]}'
    ].join("\r\n");

    console.log("Request:");
    console.log(request);

    console.log("\nResponse:");
    console.log(response);

    console.log("\nThe request contains a method, target, headers, and optional body.");
    console.log("The response contains a status, headers, and optional body.");
}

// ============================================================================
// 2. URLS
// ============================================================================

function demonstrateUrls() {
    printSection("2. URL structure");

    const url = new URL(
        "https://api.example.com:443/users/profile?page=2&active=true#details"
    );

    console.log("Protocol:", url.protocol);
    console.log("Host:", url.host);
    console.log("Hostname:", url.hostname);
    console.log("Port:", url.port || "(default)");
    console.log("Path:", url.pathname);
    console.log("Query:", url.search);
    console.log("Fragment:", url.hash);

    for (const [key, value] of url.searchParams.entries()) {
        console.log(`Query parameter: ${key} = ${value}`);
    }

    console.log(
        "\nThe URL fragment is normally processed by the browser and is not sent"
        + " to the server as part of the HTTP request target."
    );
}

// ============================================================================
// 3. METHODS
// ============================================================================

class ResourceStore {
    constructor() {
        this.resources = new Map();
        this.nextId = 1;
    }

    get(id = null) {
        if (id === null) {
            return [...this.resources.values()];
        }

        return this.resources.get(id) ?? null;
    }

    create(name, description) {
        const resource = {
            id: this.nextId++,
            name,
            description
        };

        this.resources.set(resource.id, resource);
        return resource;
    }

    replace(id, name, description) {
        if (!this.resources.has(id)) {
            return null;
        }

        const resource = { id, name, description };
        this.resources.set(id, resource);
        return resource;
    }

    patch(id, changes) {
        const existing = this.resources.get(id);

        if (!existing) {
            return null;
        }

        const updated = {
            ...existing,
            ...changes,
            id
        };

        this.resources.set(id, updated);
        return updated;
    }

    delete(id) {
        return this.resources.delete(id);
    }
}

function demonstrateMethods() {
    printSection("3. HTTP methods");

    const store = new ResourceStore();

    const created = store.create(
        "HTTP",
        "Application communication protocol"
    );

    console.log("POST:", created);
    console.log("GET:", store.get());

    console.log(
        "PUT:",
        store.replace(
            created.id,
            "HTTP/1.1",
            "Request-response protocol"
        )
    );

    console.log(
        "PATCH:",
        store.patch(
            created.id,
            { description: "Partially modified representation" }
        )
    );

    console.log("DELETE:", store.delete(created.id));

    const methods = {
        GET: "Retrieve a representation",
        POST: "Submit data or trigger processing",
        PUT: "Replace a representation",
        PATCH: "Partially modify a representation",
        DELETE: "Delete a resource",
        HEAD: "Retrieve response metadata without the normal body",
        OPTIONS: "Discover supported communication options",
        TRACE: "Diagnostic request method, commonly disabled",
        CONNECT: "Establish a tunnel through a proxy"
    };

    for (const [method, meaning] of Object.entries(methods)) {
        console.log(`${method.padEnd(8)} -> ${meaning}`);
    }

    console.log(
        "\nGET and HEAD are safe methods. PUT and DELETE are idempotent by"
        + " definition. POST is generally not idempotent."
    );
}

// ============================================================================
// 4. STATUS CODES
// ============================================================================

function statusCategory(status) {
    if (status >= 100 && status <= 199) return "Informational";
    if (status >= 200 && status <= 299) return "Success";
    if (status >= 300 && status <= 399) return "Redirection";
    if (status >= 400 && status <= 499) return "Client error";
    if (status >= 500 && status <= 599) return "Server error";
    return "Invalid status";
}

function demonstrateStatusCodes() {
    printSection("4. Status codes");

    const codes = {
        200: "OK",
        201: "Created",
        202: "Accepted",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        304: "Not Modified",
        307: "Temporary Redirect",
        308: "Permanent Redirect",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        415: "Unsupported Media Type",
        422: "Unprocessable Content",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    };

    for (const [code, phrase] of Object.entries(codes)) {
        console.log(`${code}: ${phrase} (${statusCategory(Number(code))})`);
    }

    console.log(
        "\n401 concerns authentication. 403 concerns authorization."
        + " The exact application semantics should be documented by the API."
    );
}

// ============================================================================
// 5. HEADERS
// ============================================================================

function demonstrateHeaders() {
    printSection("5. Headers");

    const requestHeaders = {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: "Bearer example-token",
        "User-Agent": "HttpStudyClient/1.0",
        "Cache-Control": "no-cache"
    };

    const responseHeaders = {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        ETag: '"resource-7"',
        "Set-Cookie": "session_id=abc123; HttpOnly; Secure; SameSite=Lax"
    };

    console.log("Request headers:");
    console.table(requestHeaders);

    console.log("Response headers:");
    console.table(responseHeaders);

    console.log(
        "Accept describes response formats the client can receive."
    );
    console.log(
        "Content-Type describes the representation being sent in that message."
    );
}

// ============================================================================
// 6. JSON
// ============================================================================

function demonstrateJson() {
    printSection("6. JSON request and response");

    const payload = {
        name: "Ada",
        role: "engineer",
        active: true,
        skills: ["JavaScript", "HTTP"]
    };

    const serialized = JSON.stringify(payload);
    const parsed = JSON.parse(serialized);

    console.log("Object:", payload);
    console.log("JSON:", serialized);
    console.log("Parsed object:", parsed);
}

// ============================================================================
// 7. COOKIES
// ============================================================================

function parseCookieHeader(cookieHeader) {
    const cookies = {};

    for (const part of cookieHeader.split(";")) {
        const separator = part.indexOf("=");

        if (separator === -1) {
            continue;
        }

        const name = part.slice(0, separator).trim();
        const value = part.slice(separator + 1).trim();

        cookies[name] = value;
    }

    return cookies;
}

function demonstrateCookies() {
    printSection("7. Cookies");

    const setCookie =
        "session_id=abc123; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Lax";

    console.log("Set-Cookie:", setCookie);

    const requestCookie = "session_id=abc123; theme=dark";
    console.log("Cookie:", requestCookie);
    console.log("Parsed cookies:", parseCookieHeader(requestCookie));

    console.log("\nImportant attributes:");
    console.log("Secure: cookie should be sent over HTTPS.");
    console.log("HttpOnly: browser scripts cannot normally read the cookie.");
    console.log("SameSite: controls cross-site cookie behavior.");
    console.log("Max-Age: specifies lifetime in seconds.");
    console.log("Path: limits URL paths where the cookie is sent.");
}

// ============================================================================
// 8. SESSIONS
// ============================================================================

class SessionManager {
    constructor(lifetimeMs = 60 * 60 * 1000) {
        this.lifetimeMs = lifetimeMs;
        this.sessions = new Map();
    }

    create(userId) {
        const sessionId = crypto.randomBytes(32).toString("base64url");

        const session = {
            sessionId,
            userId,
            createdAt: Date.now(),
            expiresAt: Date.now() + this.lifetimeMs
        };

        this.sessions.set(sessionId, session);
        return session;
    }

    get(sessionId) {
        const session = this.sessions.get(sessionId);

        if (!session) {
            return null;
        }

        if (Date.now() >= session.expiresAt) {
            this.sessions.delete(sessionId);
            return null;
        }

        return session;
    }

    revoke(sessionId) {
        return this.sessions.delete(sessionId);
    }
}

function demonstrateSessions() {
    printSection("8. Sessions");

    const sessions = new SessionManager();
    const session = sessions.create("user-42");

    console.log("Session:", session);
    console.log("Lookup:", sessions.get(session.sessionId));

    sessions.revoke(session.sessionId);

    console.log("After logout:", sessions.get(session.sessionId));

    console.log(
        "\nA common session architecture stores only a random session ID in"
        + " the browser cookie while keeping session state on the server."
    );
}

// ============================================================================
// 9. AUTHENTICATION
// ============================================================================

function demonstrateAuthentication() {
    printSection("9. Authentication headers");

    const username = "alice";
    const password = "example-password";

    const basicCredentials = Buffer
        .from(`${username}:${password}`, "utf8")
        .toString("base64");

    console.log(`Authorization: Basic ${basicCredentials}`);
    console.log("Authorization: Bearer example-token");

    console.log(
        "\nBase64 is encoding, not encryption. Credentials and bearer tokens"
        + " require transport protection such as HTTPS."
    );
}

// ============================================================================
// 10. REQUEST VALIDATION
// ============================================================================

function validateUserPayload(headers, body) {
    const contentType = String(headers["content-type"] || "")
        .split(";")[0]
        .trim()
        .toLowerCase();

    if (contentType !== "application/json") {
        return {
            valid: false,
            status: 415,
            error: "Content-Type must be application/json"
        };
    }

    let data;

    try {
        data = JSON.parse(body);
    } catch {
        return {
            valid: false,
            status: 400,
            error: "Malformed JSON"
        };
    }

    if (
        !data ||
        typeof data !== "object" ||
        Array.isArray(data)
    ) {
        return {
            valid: false,
            status: 400,
            error: "JSON body must be an object"
        };
    }

    if (
        typeof data.name !== "string" ||
        data.name.trim().length === 0
    ) {
        return {
            valid: false,
            status: 422,
            error: "name must be a non-empty string"
        };
    }

    return {
        valid: true,
        status: 200,
        data
    };
}

// ============================================================================
// 11. LOCAL HTTP SERVER
// ============================================================================

const sessionManager = new SessionManager();
const users = new Map();
let nextUserId = 1;

function sendJson(response, status, payload, extraHeaders = {}) {
    const body = JSON.stringify(payload, null, 2);

    response.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(body),
        "Cache-Control": "no-store",
        ...extraHeaders
    });

    response.end(body);
}

function readRequestBody(request, maxBytes = 1_000_000) {
    return new Promise((resolve, reject) => {
        let body = "";
        let receivedBytes = 0;

        request.setEncoding("utf8");

        request.on("data", chunk => {
            receivedBytes += Buffer.byteLength(chunk);

            if (receivedBytes > maxBytes) {
                reject(new Error("Request body too large"));
                request.destroy();
                return;
            }

            body += chunk;
        });

        request.on("end", () => resolve(body));
        request.on("error", reject);
    });
}

async function handleRequest(request, response) {
    const requestUrl = new URL(
        request.url,
        `http://${request.headers.host || "localhost"}`
    );

    const method = request.method;
    const path = requestUrl.pathname;

    if (method === "GET" && path === "/") {
        sendJson(response, 200, {
            message: "HTTP study server",
            method,
            path,
            query: Object.fromEntries(requestUrl.searchParams)
        });
        return;
    }

    if (method === "GET" && path === "/status") {
        sendJson(response, 200, {
            status: "ok",
            time: new Date().toISOString()
        });
        return;
    }

    if (method === "HEAD" && path === "/status") {
        const body = JSON.stringify({ status: "ok" });

        response.writeHead(200, {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body)
        });

        response.end();
        return;
    }

    if (method === "OPTIONS") {
        response.writeHead(204, {
            Allow: "GET, HEAD, POST, OPTIONS",
            "Access-Control-Allow-Methods":
                "GET, HEAD, POST, OPTIONS",
            "Access-Control-Allow-Headers":
                "Content-Type, Authorization"
        });

        response.end();
        return;
    }

    if (method === "POST" && path === "/login") {
        let body;

        try {
            body = await readRequestBody(request);
        } catch {
            sendJson(response, 413, {
                error: "Request body too large"
            });
            return;
        }

        let credentials;

        try {
            credentials = JSON.parse(body);
        } catch {
            sendJson(response, 400, {
                error: "Malformed JSON"
            });
            return;
        }

        if (
            credentials.username !== "alice" ||
            credentials.password !== "correct-password"
        ) {
            sendJson(response, 401, {
                error: "Invalid credentials"
            });
            return;
        }

        const session = sessionManager.create("alice");

        sendJson(
            response,
            200,
            {
                message: "Login successful"
            },
            {
                "Set-Cookie":
                    `session_id=${session.sessionId}; Max-Age=3600; ` +
                    "Path=/; HttpOnly; SameSite=Lax"
            }
        );

        return;
    }

    if (method === "GET" && path === "/protected") {
        const cookies = parseCookieHeader(
            request.headers.cookie || ""
        );

        const session = cookies.session_id
            ? sessionManager.get(cookies.session_id)
            : null;

        if (!session) {
            sendJson(response, 401, {
                error: "Authentication required"
            });
            return;
        }

        sendJson(response, 200, {
            message: "Protected resource",
            userId: session.userId
        });

        return;
    }

    if (method === "POST" && path === "/users") {
        let body;

        try {
            body = await readRequestBody(request);
        } catch {
            sendJson(response, 413, {
                error: "Request body too large"
            });
            return;
        }

        const validation = validateUserPayload(
            request.headers,
            body
        );

        if (!validation.valid) {
            sendJson(response, validation.status, {
                error: validation.error
            });
            return;
        }

        const user = {
            id: nextUserId++,
            ...validation.data
        };

        users.set(user.id, user);

        sendJson(
            response,
            201,
            user,
            {
                Location: `/users/${user.id}`
            }
        );

        return;
    }

    if (method === "GET" && path.startsWith("/users/")) {
        const id = Number(path.split("/")[2]);

        if (!Number.isInteger(id)) {
            sendJson(response, 400, {
                error: "Invalid user ID"
            });
            return;
        }

        const user = users.get(id);

        if (!user) {
            sendJson(response, 404, {
                error: "User not found"
            });
            return;
        }

        sendJson(response, 200, user);
        return;
    }

    sendJson(response, 404, {
        error: "Resource not found",
        method,
        path
    });
}

function startServer() {
    const server = http.createServer((request, response) => {
        const startedAt = process.hrtime.bigint();

        handleRequest(request, response)
            .catch(error => {
                console.error(error);

                if (!response.headersSent) {
                    sendJson(response, 500, {
                        error: "Internal server error"
                    });
                } else {
                    response.destroy();
                }
            })
            .finally(() => {
                const durationMs =
                    Number(process.hrtime.bigint() - startedAt) / 1e6;

                console.log(
                    `${request.method} ${request.url} -> ` +
                    `${response.statusCode} (${durationMs.toFixed(2)} ms)`
                );
            });
    });

    return server;
}

// ============================================================================
// 12. CLIENT REQUESTS
// ============================================================================

function makeRequest(options, body = null) {
    return new Promise((resolve, reject) => {
        const request = http.request(options, response => {
            let responseBody = "";

            response.setEncoding("utf8");

            response.on("data", chunk => {
                responseBody += chunk;
            });

            response.on("end", () => {
                resolve({
                    status: response.statusCode,
                    headers: response.headers,
                    body: responseBody
                });
            });
        });

        request.setTimeout(5000, () => {
            request.destroy(new Error("Request timeout"));
        });

        request.on("error", reject);

        if (body !== null) {
            request.write(body);
        }

        request.end();
    });
}

async function demonstrateClient(server) {
    printSection("12. Node.js HTTP client");

    const port = server.address().port;

    const statusResponse = await makeRequest({
        hostname: "127.0.0.1",
        port,
        path: "/status",
        method: "GET",
        headers: {
            Accept: "application/json"
        }
    });

    console.log("GET /status:", statusResponse);

    const body = JSON.stringify({
        name: "Grace",
        role: "systems engineer"
    });

    const createdResponse = await makeRequest({
        hostname: "127.0.0.1",
        port,
        path: "/users",
        method: "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body)
        }
    }, body);

    console.log("POST /users:", createdResponse);

    const missingResponse = await makeRequest({
        hostname: "127.0.0.1",
        port,
        path: "/missing",
        method: "GET"
    });

    console.log("GET /missing:", missingResponse);
}

// ============================================================================
// 13. REDIRECTS
// ============================================================================

function demonstrateRedirects() {
    printSection("13. Redirects");

    const redirects = {
        301: "Permanent redirect",
        302: "Temporary/found response",
        303: "See another resource using GET",
        307: "Temporary redirect preserving method",
        308: "Permanent redirect preserving method"
    };

    console.table(redirects);
}

// ============================================================================
// 14. CACHE VALIDATION
// ============================================================================

function demonstrateCaching() {
    printSection("14. Caching");

    const headers = {
        "Cache-Control": "public, max-age=3600",
        ETag: '"version-42"',
        "Last-Modified": "Wed, 23 Sep 2026 05:00:00 GMT"
    };

    console.table(headers);

    console.log("Client can later send:");
    console.log('If-None-Match: "version-42"');

    console.log(
        "If unchanged, the server can respond with 304 Not Modified."
    );
}

// ============================================================================
// 15. RETRIES
// ============================================================================

function retryDelay(attempt, baseMs = 250, maxMs = 8000) {
    const exponential = Math.min(
        maxMs,
        baseMs * (2 ** attempt)
    );

    const jitter = Math.random() * baseMs;

    return Math.min(maxMs, exponential + jitter);
}

function demonstrateRetries() {
    printSection("15. Timeouts and retries");

    for (let attempt = 0; attempt < 5; attempt++) {
        console.log(
            `Attempt ${attempt}: ${retryDelay(attempt).toFixed(0)} ms`
        );
    }

    console.log(
        "Retry decisions should consider status, method semantics,"
        + " idempotency, timeout type, and server capacity."
    );
}

// ============================================================================
// 16. SECURITY
// ============================================================================

function demonstrateSecurity() {
    printSection("16. HTTP security");

    const token = crypto.randomBytes(32).toString("base64url");
    const digest = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

    console.log("Example secure random token:", token);
    console.log("SHA-256 digest:", digest);

    const rules = [
        "Use HTTPS for sensitive traffic.",
        "Do not put passwords or access tokens in URLs.",
        "Protect session identifiers.",
        "Use Secure and HttpOnly cookie attributes where appropriate.",
        "Configure SameSite deliberately.",
        "Validate all client-controlled input.",
        "Limit request body sizes.",
        "Rate-limit sensitive endpoints.",
        "Do not log secrets.",
        "Treat headers as untrusted input."
    ];

    rules.forEach((rule, index) => {
        console.log(`${index + 1}. ${rule}`);
    });
}

// ============================================================================
// 17. DEVTOOLS WORKFLOW
// ============================================================================

function demonstrateDevToolsWorkflow() {
    printSection("17. Browser DevTools Network workflow");

    const steps = [
        "Open Developer Tools.",
        "Select Network.",
        "Reload the page.",
        "Trigger an application action.",
        "Select the resulting request.",
        "Inspect the Request URL and method.",
        "Inspect request headers.",
        "Inspect query parameters.",
        "Inspect request payload.",
        "Inspect cookies.",
        "Inspect response status.",
        "Inspect response headers.",
        "Inspect response body.",
        "Inspect timing and connection information."
    ];

    steps.forEach((step, index) => {
        console.log(`${index + 1}. ${step}`);
    });
}

// ============================================================================
// 18. CURL
// ============================================================================

function demonstrateCurl() {
    printSection("18. curl commands");

    const commands = [
        "curl https://example.com",
        "curl -i https://example.com",
        "curl -I https://example.com",
        "curl -v https://example.com",
        "curl -X POST https://example.com/users",
        "curl -H 'Accept: application/json' https://example.com/users",
        "curl -H 'Content-Type: application/json' -d '{\"name\":\"Ada\"}' https://example.com/users",
        "curl -b 'session_id=abc123' https://example.com/protected",
        "curl -c cookies.txt -b cookies.txt https://example.com/",
        "curl -L https://example.com/redirect"
    ];

    commands.forEach(command => console.log("$ " + command));
}

// ============================================================================
// 19. COMPLETE APPLICATION DEMONSTRATION
// ============================================================================

async function runCompleteDemo() {
    printSection("HTTP comprehensive JavaScript demonstration");

    demonstrateHttpMessages();
    demonstrateUrls();
    demonstrateMethods();
    demonstrateStatusCodes();
    demonstrateHeaders();
    demonstrateJson();
    demonstrateCookies();
    demonstrateSessions();
    demonstrateAuthentication();
    demonstrateRedirects();
    demonstrateCaching();
    demonstrateRetries();
    demonstrateSecurity();
    demonstrateDevToolsWorkflow();
    demonstrateCurl();

    const server = startServer();

    await new Promise(resolve => {
        server.listen(0, "127.0.0.1", resolve);
    });

    try {
        console.log(
            `\nLocal server running on http://127.0.0.1:${server.address().port}`
        );

        await demonstrateClient(server);

        const port = server.address().port;

        const loginBody = JSON.stringify({
            username: "alice",
            password: "correct-password"
        });

        const login = await makeRequest({
            hostname: "127.0.0.1",
            port,
            path: "/login",
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(loginBody)
            }
        }, loginBody);

        console.log("\nPOST /login:", login);

        const setCookie = login.headers["set-cookie"];

        if (setCookie && setCookie.length > 0) {
            const sessionCookie = setCookie[0]
                .split(";", 1)[0];

            const protectedResponse = await makeRequest({
                hostname: "127.0.0.1",
                port,
                path: "/protected",
                method: "GET",
                headers: {
                    Cookie: sessionCookie
                }
            });

            console.log(
                "\nGET /protected with session:",
                protectedResponse
            );
        }
    } finally {
        await new Promise(resolve => server.close(resolve));
        console.log("\nLocal server stopped.");
    }
}

runCompleteDemo().catch(error => {
    console.error("Fatal error:", error);
    process.exitCode = 1;
});
