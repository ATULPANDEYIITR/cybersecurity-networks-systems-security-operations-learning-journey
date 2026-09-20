# File: tests/test_inspector.py

# File: tests/test_inspector.py

from port_inspector.inspector import (
    classify_service,
    filter_endpoints,
)
from port_inspector.models import Endpoint


def test_common_service_classification() -> None:
    assert classify_service("tcp", 443) == "HTTPS"
    assert classify_service("udp", 53) == "DNS"


def test_unknown_service_is_none() -> None:
    assert classify_service("tcp", 49123) is None


def test_filter_by_protocol() -> None:
    endpoints = [
        Endpoint("tcp", "127.0.0.1", 8000, state="LISTEN"),
        Endpoint("udp", "127.0.0.1", 5353, state="NONE"),
    ]

    result = filter_endpoints(endpoints, protocol="tcp")

    assert len(result) == 1
    assert result[0].protocol == "tcp"


def test_filter_by_port() -> None:
    endpoints = [
        Endpoint("tcp", "127.0.0.1", 8000, state="LISTEN"),
        Endpoint("tcp", "127.0.0.1", 9000, state="LISTEN"),
    ]

    result = filter_endpoints(endpoints, port=9000)

    assert [endpoint.local_port for endpoint in result] == [9000]


def test_filter_listening() -> None:
    endpoints = [
        Endpoint("tcp", "127.0.0.1", 8000, state="LISTEN"),
        Endpoint("tcp", "127.0.0.1", 8001, state="ESTABLISHED"),
    ]

    result = filter_endpoints(endpoints, listening_only=True)

    assert len(result) == 1
    assert result[0].local_port == 8000
