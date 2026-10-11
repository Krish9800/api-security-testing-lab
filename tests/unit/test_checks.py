from datetime import UTC, datetime
from unittest.mock import MagicMock

from apisec.checks.bfla import BFLACheck
from apisec.checks.bola import BOLACheck
from apisec.checks.broken_auth import BrokenAuthCheck
from apisec.checks.mass_assignment import MassAssignmentCheck
from apisec.checks.misconfig import SecurityMisconfigCheck
from apisec.checks.rate_limiting import RateLimitingCheck
from apisec.checks.runner import SecurityCheckRunner
from apisec.core.http_client import SecurityHTTPClient
from apisec.models.enums import HTTPMethod, OWASPCategory
from apisec.models.finding import HTTPTransaction
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint, APIParameter


def _mock_client(
    status: int, text: str, headers: dict[str, str] | None = None
) -> SecurityHTTPClient:
    client = SecurityHTTPClient()
    mock_resp = MagicMock()
    mock_resp.status_code = status
    mock_resp.text = text
    mock_resp.headers = headers or {"Content-Type": "application/json"}
    mock_resp.json.return_value = {
        "role": "admin",
        "id": 2,
        "user": "target",
        "is_admin": True,
    }
    tx = HTTPTransaction(
        request_id="req-mock-123",
        method=HTTPMethod.GET,
        url="http://test.api/mock",
        request_headers={},
        request_body=None,
        response_status=status,
        response_headers=mock_resp.headers,
        response_body=text,
        response_time_ms=10.0,
        timestamp=datetime.now(UTC),
    )
    client.send_request = MagicMock(return_value=(mock_resp, tx))  # type: ignore[method-assign]
    return client


def test_bola_check_vulnerable() -> None:
    """Verify BOLACheck flags cross-tenant 200 responses."""
    check = BOLACheck()
    param = APIParameter(name="id", location="path", param_type="integer", required=True)
    endpoint = APIEndpoint(path="/users/{id}", method=HTTPMethod.GET, parameters=[param])
    config = ScanConfig(
        base_url="http://test.api",
        auth_token_user_a="tokenA",
        auth_token_user_b="tokenB",
    )
    client = _mock_client(200, '{"id": 2, "user": "userB"}')

    findings = check.execute(endpoint, client, config)
    assert len(findings) == 1
    assert findings[0].category == OWASPCategory.API1_BOLA


def test_broken_auth_check_vulnerable() -> None:
    """Verify BrokenAuthCheck flags unprotected routes and invalid token acceptance."""
    check = BrokenAuthCheck()
    endpoint = APIEndpoint(path="/secret/data", method=HTTPMethod.GET, auth_required=True)
    config = ScanConfig(base_url="http://test.api")
    client = _mock_client(200, '{"secret": "val"}')

    findings = check.execute(endpoint, client, config)
    assert len(findings) >= 1
    assert findings[0].category == OWASPCategory.API2_BROKEN_AUTH


def test_mass_assignment_check_vulnerable() -> None:
    """Verify MassAssignmentCheck detects reflected administrative privilege fields."""
    check = MassAssignmentCheck()
    endpoint = APIEndpoint(path="/users/{id}", method=HTTPMethod.PUT)
    config = ScanConfig(base_url="http://test.api", auth_token_user_a="tokenA")
    client = _mock_client(200, '{"id": 1, "role": "admin"}')

    findings = check.execute(endpoint, client, config)
    assert len(findings) == 1
    assert findings[0].category == OWASPCategory.API3_BOPLA


def test_rate_limiting_check_vulnerable() -> None:
    """Verify RateLimitingCheck flags endpoints that do not enforce 429 status."""
    check = RateLimitingCheck()
    endpoint = APIEndpoint(path="/search", method=HTTPMethod.GET)
    config = ScanConfig(base_url="http://test.api")
    client = _mock_client(200, '{"results": []}')

    findings = check.execute(endpoint, client, config)
    assert len(findings) == 1
    assert findings[0].category == OWASPCategory.API4_UNRESTRICTED_RESOURCES


def test_bfla_check_vulnerable() -> None:
    """Verify BFLACheck detects standard tokens accessing administrative routes."""
    check = BFLACheck()
    endpoint = APIEndpoint(path="/api/v1/admin/users", method=HTTPMethod.GET, tags=["admin"])
    config = ScanConfig(base_url="http://test.api", auth_token_user_a="user_token")
    client = _mock_client(200, '[{"admin": true}]')

    findings = check.execute(endpoint, client, config)
    assert len(findings) == 1
    assert findings[0].category == OWASPCategory.API5_BFLA


def test_security_misconfig_cors_vulnerable() -> None:
    """Verify SecurityMisconfigCheck detects CORS wildcard origin reflection with credentials."""
    check = SecurityMisconfigCheck()
    endpoint = APIEndpoint(path="/public", method=HTTPMethod.GET)
    config = ScanConfig(base_url="http://test.api")
    headers = {
        "access-control-allow-origin": "https://evil-attacker.com",
        "access-control-allow-credentials": "true",
    }
    client = _mock_client(200, '{"ok": true}', headers=headers)

    findings = check.execute(endpoint, client, config)
    assert len(findings) == 1
    assert findings[0].category == OWASPCategory.API7_MISCONFIG


def test_security_runner() -> None:
    """Verify runner coordinates multiple checks across endpoints."""
    runner = SecurityCheckRunner()
    endpoint = APIEndpoint(path="/public", method=HTTPMethod.GET)
    config = ScanConfig(base_url="http://test.api")
    client = _mock_client(200, '{"ok": true}')

    # Should run smoothly without exceptions
    findings = runner.run_all([endpoint], client, config)
    assert isinstance(findings, list)
