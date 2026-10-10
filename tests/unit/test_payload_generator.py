"""Unit tests for payload generator."""

from apisec.core.payload_generator import PayloadGenerator
from apisec.models.enums import HTTPMethod
from apisec.models.spec import APIEndpoint, APIParameter


def test_mass_assignment_payload_generation() -> None:
    """Verify malicious administrative fields are appended to payload."""
    base = {"username": "alice", "email": "alice@test.org"}
    payload = PayloadGenerator.generate_mass_assignment_body(base)

    assert payload["username"] == "alice"
    assert payload["is_admin"] is True
    assert payload["role"] == "admin"


def test_fuzzed_parameters_generation() -> None:
    """Verify parameter variations for integer and string endpoints."""
    param = APIParameter(name="user_id", location="path", param_type="integer", required=True)
    endpoint = APIEndpoint(path="/users/{user_id}", method=HTTPMethod.GET, parameters=[param])

    fuzzed = PayloadGenerator.generate_fuzzed_parameters(endpoint)
    assert len(fuzzed) >= 2
    assert fuzzed[0]["user_id"] == "1"
    assert fuzzed[1]["user_id"] == "9999999"
