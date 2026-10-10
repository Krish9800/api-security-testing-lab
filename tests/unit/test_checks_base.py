"""Unit tests covering BaseSecurityCheck abstract class and client exception paths."""

from unittest.mock import MagicMock, patch

from apisec.checks.base import BaseSecurityCheck
from apisec.core.http_client import SecurityHTTPClient
from apisec.models.enums import HTTPMethod, OWASPCategory, Severity
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint


class DummySecurityCheck(BaseSecurityCheck):
    """Concrete dummy implementation for testing."""

    category = OWASPCategory.API1_BOLA
    default_severity = Severity.HIGH
    name = "Dummy Check"
    description = "Tests BaseSecurityCheck interface."

    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        return []


def test_base_security_check_interface() -> None:
    """Verify BaseSecurityCheck subclasses can be instantiated and executed."""
    check = DummySecurityCheck()
    endpoint = APIEndpoint(path="/test", method=HTTPMethod.GET)
    client = SecurityHTTPClient()
    config = ScanConfig(base_url="http://localhost")

    findings = check.execute(endpoint, client, config)
    assert findings == []
    assert check.category == OWASPCategory.API1_BOLA


@patch("httpx.Client.request")
def test_send_request_exception_handling(mock_request: MagicMock) -> None:
    """Verify send_request gracefully catches connection errors."""
    mock_request.side_effect = RuntimeError("Connection dropped")

    client = SecurityHTTPClient(base_url="http://test.api")
    resp, tx = client.send_request(
        method=HTTPMethod.POST,
        path="/submit",
        json_data={"key": "val"},
    )

    assert resp.status_code == 500
    assert tx.response_status == 0
    assert "Connection dropped" in str(tx.response_body)
    assert tx.request_body == '{"key": "val"}'
