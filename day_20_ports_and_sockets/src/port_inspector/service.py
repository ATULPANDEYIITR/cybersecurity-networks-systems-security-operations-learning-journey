# File: src/port_inspector/service.py

# File: src/port_inspector/service.py

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .inspector import filter_endpoints, inspect_endpoints
from .models import validate_port

logging.basicConfig(
    level=getattr(logging, os.getenv("PORT_INSPECTOR_LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(
    title="Local Ports and Sockets API",
    version="1.0.0",
    description="Local educational API for inspecting TCP and UDP endpoints.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "null",
    ],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    """Return service health."""
    return {"status": "ok"}


@app.get("/api/endpoints")
def endpoints(
    protocol: str | None = Query(default=None),
    port: int | None = Query(default=None, ge=0, le=65535),
    listening: bool = Query(default=False),
) -> list[dict[str, Any]]:
    """Return a snapshot of locally visible TCP and UDP endpoints."""
    try:
        snapshot = inspect_endpoints()
        filtered = filter_endpoints(
            snapshot,
            protocol=protocol,
            port=port,
            listening_only=listening,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return [endpoint.to_dict() for endpoint in filtered]


@app.get("/api/endpoints/listening")
def listening_endpoints() -> list[dict[str, Any]]:
    """Return locally visible TCP listeners."""
    snapshot = inspect_endpoints()
    filtered = filter_endpoints(snapshot, listening_only=True)
    return [endpoint.to_dict() for endpoint in filtered]


@app.get("/api/endpoints/{port}")
def endpoint_by_port(port: int) -> list[dict[str, Any]]:
    """Return endpoints whose local port matches the requested number."""
    try:
        validate_port(port)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    snapshot = inspect_endpoints()
    filtered = filter_endpoints(snapshot, port=port)
    return [endpoint.to_dict() for endpoint in filtered]
