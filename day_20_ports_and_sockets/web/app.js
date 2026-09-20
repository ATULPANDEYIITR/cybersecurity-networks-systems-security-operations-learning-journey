// File: web/app.js

const API_BASE = "http://127.0.0.1:8000";

const protocolElement = document.getElementById("protocol");
const portElement = document.getElementById("port");
const listeningElement = document.getElementById("listening");
const refreshButton = document.getElementById("refresh");
const statusElement = document.getElementById("status");
const countElement = document.getElementById("count");
const tableElement = document.getElementById("endpoint-table");

function createCell(value) {
    const cell = document.createElement("td");
    cell.textContent = value ?? "-";
    return cell;
}

function renderEndpoints(endpoints) {
    tableElement.replaceChildren();

    for (const endpoint of endpoints) {
        const row = document.createElement("tr");

        row.append(
            createCell(endpoint.protocol.toUpperCase()),
            createCell(`${endpoint.local_address}:${endpoint.local_port}`),
            createCell(
                endpoint.remote_address && endpoint.remote_port !== null
                    ? `${endpoint.remote_address}:${endpoint.remote_port}`
                    : "-"
            ),
            createCell(endpoint.state),
            createCell(endpoint.pid ?? "-"),
            createCell(endpoint.process_name ?? "-"),
            createCell(endpoint.service ?? "-")
        );

        tableElement.appendChild(row);
    }

    countElement.textContent =
        `${endpoints.length} endpoint${endpoints.length === 1 ? "" : "s"}`;
}

async function loadEndpoints() {
    statusElement.classList.remove("error");
    statusElement.textContent = "Loading...";

    const params = new URLSearchParams();

    if (protocolElement.value) {
        params.set("protocol", protocolElement.value);
    }

    if (portElement.value !== "") {
        params.set("port", portElement.value);
    }

    if (listeningElement.checked) {
        params.set("listening", "true");
    }

    try {
        const response = await fetch(`${API_BASE}/api/endpoints?${params}`);

        if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            throw new Error(body.detail || `HTTP ${response.status}`);
        }

        const endpoints = await response.json();
        renderEndpoints(endpoints);
        statusElement.textContent = "Connected";
    } catch (error) {
        tableElement.replaceChildren();
        countElement.textContent = "0 endpoints";
        statusElement.textContent = `API error: ${error.message}`;
        statusElement.classList.add("error");
    }
}

refreshButton.addEventListener("click", loadEndpoints);
protocolElement.addEventListener("change", loadEndpoints);
listeningElement.addEventListener("change", loadEndpoints);

loadEndpoints();
