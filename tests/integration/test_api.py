"""Integration tests for FastAPI REST control plane."""

from starlette.testclient import TestClient

from apisec.api.app import create_api_app


def test_api_health() -> None:
    """Verify health endpoint responds with 200."""
    app = create_api_app()
    with TestClient(app) as client:
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"


def test_api_stats() -> None:
    """Verify system stats endpoint."""
    app = create_api_app()
    with TestClient(app) as client:
        res = client.get("/api/v1/stats")
        assert res.status_code == 200
        assert "total_sessions" in res.json()


def test_api_scans_workflow() -> None:
    """Verify triggering, listing, and retrieving scan reports."""
    app = create_api_app()
    with TestClient(app) as client:
        # Trigger scan with fallback routes
        payload = {
            "target_url": "http://testserver",
            "auth_token_user_a": "tokenA",
        }
        res_post = client.post("/api/v1/scans", json=payload)
        assert res_post.status_code == 201
        session_data = res_post.json()
        session_id = session_data["session_id"]
        assert session_id.startswith("scan-")

        # List scans
        res_list = client.get("/api/v1/scans?limit=10")
        assert res_list.status_code == 200
        assert any(s["session_id"] == session_id for s in res_list.json())

        # Get specific scan
        res_get = client.get(f"/api/v1/scans/{session_id}")
        assert res_get.status_code == 200
        assert res_get.json()["session_id"] == session_id

        # Get JSON report
        res_rep_json = client.get(f"/api/v1/scans/{session_id}/report?report_format=json")
        assert res_rep_json.status_code == 200

        # Get Markdown report
        res_rep_md = client.get(f"/api/v1/scans/{session_id}/report?report_format=markdown")
        assert res_rep_md.status_code == 200
        assert res_rep_md.json()["format"] == "markdown"


def test_api_scan_not_found() -> None:
    """Verify 404 for non-existent scan ID."""
    app = create_api_app()
    with TestClient(app) as client:
        res = client.get("/api/v1/scans/non-existent-scan")
        assert res.status_code == 404

        res_rep = client.get("/api/v1/scans/non-existent-scan/report")
        assert res_rep.status_code == 404


def test_api_trigger_scan_bad_spec() -> None:
    """Verify 400 error when invalid OpenAPI spec URL is provided."""
    app = create_api_app()
    with TestClient(app) as client:
        payload = {
            "target_url": "http://testserver",
            "openapi_spec_url": "http://invalid-nonexistent-spec-url.invalid/spec.json",
        }
        res = client.post("/api/v1/scans", json=payload)
        assert res.status_code == 400
