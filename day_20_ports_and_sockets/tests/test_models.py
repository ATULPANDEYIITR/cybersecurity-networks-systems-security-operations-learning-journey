# File: tests/test_models.py

# File: tests/test_models.py

import pytest

from port_inspector.models import Endpoint, normalize_protocol, validate_port


def test_valid_port_is_returned() -> None:
    assert validate_port(443) == 443


@pytest.mark.parametrize("port", [-1, 65536])
def test_invalid_port_range(port: int) -> None:
    with pytest.raises(ValueError):
        validate_port(port)


def test_boolean_is_not_a_port() -> None:
    with pytest.raises(TypeError):
        validate_port(True)


def test_protocol_is_normalized() -> None:
    assert normalize_protocol(" TCP ") == "tcp"


def test_invalid_protocol_is_rejected() -> None:
    with pytest.raises(ValueError):
        normalize_protocol("icmp")


def test_endpoint_serialization() -> None:
    endpoint = Endpoint(
        protocol="tcp",
        local_address="127.0.0.1",
        local_port=8080,
        state="LISTEN",
        service="HTTP development",
    )

    data = endpoint.to_dict()

    assert data["local_port"] == 8080
    assert endpoint.is_listening is True
