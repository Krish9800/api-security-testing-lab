"""Unit tests for domain models and data integrity."""

from datetime import UTC, datetime

from apisec.models.enums import HTTPMethod, OWASPCategory, ScanStatus, Severity, TestVerdict
from apisec.models.finding import HTTPTransaction, SecurityFinding
from apisec.models.session import ScanConfig, ScanSession, ScanSummary
from apisec.models.spec import APIEndpoint, APIParameter


def test_api_endpoint_model() -> None:
    """Verify endpoint representation and parameter schemas."""
    param = APIParameter(name="id", location="path", param_type="integer", required=True)
    endpoint = APIEndpoint(
        path="/api/v1/users/{id}",
        method=HTTPMethod.GET,
        summary="Get user profile",
        parameters=[param],
        auth_required=True,
    )
    assert endpoint.endpoint_key == "GET /api/v1/users/{id}"
    assert endpoint.parameters[0].name == "id"
    assert endpoint.auth_required is True


def test_finding_and_transaction_models() -> None:
    """Verify HTTPTransaction audit log and SecurityFinding serialization."""
    now = datetime.now(UTC)
    tx = HTTPTransaction(
        request_id="req-123",
        method=HTTPMethod.GET,
        url="http://target/api/users/2",
        request_headers={"Authorization": "Bearer tokenA"},
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"id": 2, "email": "userB@corp.com"}',
        response_time_ms=45.2,
        timestamp=now,
    )

    finding = SecurityFinding(
        finding_id="find-001",
        category=OWASPCategory.API1_BOLA,
        severity=Severity.HIGH,
        title="BOLA in User Profile",
        description="User A accessed User B's profile via IDOR.",
        endpoint="/api/users/2",
        method=HTTPMethod.GET,
        verdict=TestVerdict.VULNERABLE,
        evidence="Status 200 returned user B data.",
        remediation="Enforce object-level access control checks.",
        cwe_id="CWE-639",
        transaction=tx,
        detected_at=now,
    )

    assert finding.category == OWASPCategory.API1_BOLA
    assert finding.severity == Severity.HIGH
    assert finding.transaction is not None
    assert finding.transaction.response_status == 200


def test_scan_session_and_config() -> None:
    """Verify ScanConfig and ScanSession aggregation."""
    now = datetime.now(UTC)
    config = ScanConfig(
        base_url="http://localhost:8888",
        auth_token_user_a="tokenA",
        auth_token_user_b="tokenB",
    )
    assert config.base_url == "http://localhost:8888"

    summary = ScanSummary(
        total_endpoints_tested=10,
        total_checks_executed=50,
        vulnerabilities_found=2,
        critical_count=1,
        high_count=1,
    )

    session = ScanSession(
        session_id="sess-001",
        target_base_url=config.base_url,
        status=ScanStatus.COMPLETED,
        started_at=now,
        completed_at=now,
        summary=summary,
    )

    assert session.status == ScanStatus.COMPLETED
    assert session.summary.vulnerabilities_found == 2
