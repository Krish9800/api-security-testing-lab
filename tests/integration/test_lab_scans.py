"""Integration tests running security scans against the DvAPI mock vulnerable lab."""

from starlette.testclient import TestClient

from apisec.checks.runner import SecurityCheckRunner
from apisec.core.http_client import SecurityHTTPClient
from apisec.core.openapi_parser import OpenAPIParser
from apisec.lab.dvapi import create_dvapi_app
from apisec.models.enums import OWASPCategory, TestVerdict
from apisec.models.session import ScanConfig


def test_dvapi_endpoints_direct() -> None:
    """Verify mock lab endpoints respond to basic operations."""
    app = create_dvapi_app()
    with TestClient(app) as client:
        # Auth
        login_res = client.post(
            "/api/v1/auth/login", json={"username": "alice", "password": "password123"}
        )
        assert login_res.status_code == 200
        assert "access_token" in login_res.json()

        # Users profile
        user_res = client.get("/api/v1/users/1")
        assert user_res.status_code == 200
        assert user_res.json()["username"] == "alice"

        # Protected data
        prot_res = client.get("/api/v1/protected/data")
        assert prot_res.status_code == 200
        assert "secret" in prot_res.json()

        # Mass assignment update
        put_res = client.put("/api/v1/users/1/profile", json={"role": "admin", "is_admin": True})
        assert put_res.status_code == 200
        assert put_res.json()["role"] == "admin"

        # Search
        search_res = client.get("/api/v1/search?q=test")
        assert search_res.status_code == 200

        # Public ping CORS
        ping_res = client.get(
            "/api/v1/public/ping", headers={"Origin": "https://evil-attacker.com"}
        )
        assert ping_res.status_code == 200
        assert ping_res.headers.get("access-control-allow-origin") == "https://evil-attacker.com"


def test_dvapi_auth_failure_modes() -> None:
    """Verify authentication failure edge cases in DvAPI."""
    app = create_dvapi_app()
    with TestClient(app) as client:
        # Empty credentials
        bad_login = client.post("/api/v1/auth/login", json={"username": "", "password": ""})
        assert bad_login.status_code == 401

        # Unauthenticated admin delete
        unauth_del = client.delete("/api/v1/admin/users/1")
        assert unauth_del.status_code == 401


def test_dvapi_full_security_scan() -> None:
    """Execute end-to-end security check suite against DvAPI schema and endpoints."""
    app = create_dvapi_app()
    client = SecurityHTTPClient(base_url="http://testserver", app=app)
    config = ScanConfig(
        base_url="http://testserver",
        auth_token_user_a="mock-token-alice",
        auth_token_user_b="mock-token-bob",
        admin_token="mock-token-admin",
    )

    parser = OpenAPIParser()
    endpoints = parser.parse_dict(app.openapi())
    assert len(endpoints) >= 6

    runner = SecurityCheckRunner()
    findings = runner.run_all(endpoints, client, config)

    assert len(findings) >= 5

    categories_detected = {f.category for f in findings}
    assert OWASPCategory.API1_BOLA in categories_detected
    assert OWASPCategory.API2_BROKEN_AUTH in categories_detected
    assert OWASPCategory.API3_BOPLA in categories_detected
    assert OWASPCategory.API4_UNRESTRICTED_RESOURCES in categories_detected
    assert OWASPCategory.API5_BFLA in categories_detected
    assert OWASPCategory.API7_MISCONFIG in categories_detected

    for finding in findings:
        assert finding.verdict == TestVerdict.VULNERABLE
        assert finding.remediation != ""
        assert finding.transaction is not None
        assert finding.transaction.response_status in (200, 201, 204)
