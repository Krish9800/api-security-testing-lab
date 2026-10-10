"""Unit tests for SecurityHTTPClient and header redaction."""

from unittest.mock import MagicMock, patch

from apisec.core.http_client import SecurityHTTPClient
from apisec.models.enums import HTTPMethod


def test_sanitize_headers() -> None:
    """Verify Authorization, Cookies, and API keys are redacted in audit log."""
    raw_headers = {
        "Authorization": "Bearer secret_jwt_token_12345",
        "X-Api-Key": "my-secret-api-key",
        "Cookie": "session_id=abcdef",
        "Content-Type": "application/json",
        "Accept": "*/*",
    }
    sanitized = SecurityHTTPClient._sanitize_headers(raw_headers)

    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["X-Api-Key"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["Accept"] == "*/*"


@patch("httpx.Client.request")
def test_send_request_logging(mock_request: MagicMock) -> None:
    """Verify send_request records HTTPTransaction correctly."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"message": "ok"}'
    mock_resp.headers = {"Content-Type": "application/json", "Set-Cookie": "secret=1"}
    mock_request.return_value = mock_resp

    client = SecurityHTTPClient(base_url="http://test.api")
    resp, tx = client.send_request(
        method=HTTPMethod.GET,
        path="/items",
        headers={"Authorization": "Bearer test"},
    )

    assert resp.status_code == 200
    assert tx.method == HTTPMethod.GET
    assert tx.url == "http://test.api/items"
    assert tx.request_headers["Authorization"] == "[REDACTED]"
    assert tx.response_headers["Set-Cookie"] == "[REDACTED]"
    assert tx.response_status == 200
    assert tx.response_body == '{"message": "ok"}'
