"""Unit tests for SQLite storage layer and DatabaseManager."""

from datetime import UTC, datetime
from pathlib import Path

from apisec.db.database import DatabaseManager
from apisec.models.enums import HTTPMethod, OWASPCategory, ScanStatus, Severity, TestVerdict
from apisec.models.finding import HTTPTransaction, SecurityFinding
from apisec.models.session import ScanSession, ScanSummary


def _create_sample_session(session_id: str = "sess-001") -> ScanSession:
    tx = HTTPTransaction(
        request_id="req-test-1",
        method=HTTPMethod.GET,
        url="http://test.api/users/2",
        request_headers={"Authorization": "Bearer tokenA"},
        request_body=None,
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body='{"id": 2, "user": "target"}',
        response_time_ms=15.4,
        timestamp=datetime.now(UTC),
    )
    finding = SecurityFinding(
        finding_id="find-test-1",
        category=OWASPCategory.API1_BOLA,
        severity=Severity.HIGH,
        title="BOLA in GET /users/{id}",
        description="Cross-tenant access allowed.",
        endpoint="/users/{id}",
        method=HTTPMethod.GET,
        verdict=TestVerdict.VULNERABLE,
        evidence="HTTP 200 returned.",
        remediation="Enforce object checks.",
        cwe_id="CWE-639",
        transaction=tx,
        detected_at=datetime.now(UTC),
    )
    summary = ScanSummary(
        total_endpoints_tested=1,
        total_checks_executed=5,
        vulnerabilities_found=1,
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
    )
    return ScanSession(
        session_id=session_id,
        target_base_url="http://test.api",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        findings=[finding],
        summary=summary,
    )


def test_database_init(tmp_path: Path) -> None:
    """Verify database initialization creates all tables and executes pragmas."""
    db_file = tmp_path / "test_apisec.db"
    db = DatabaseManager(db_file)
    assert db_file.exists()

    with db._get_connection() as conn:
        tables = [
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]
        assert "scan_sessions" in tables
        assert "scan_findings" in tables
        assert "http_transactions" in tables


def test_save_and_get_session(tmp_path: Path) -> None:
    """Verify storing and retrieving a complete scan session with findings."""
    db_file = tmp_path / "test_apisec.db"
    db = DatabaseManager(db_file)
    session = _create_sample_session("sess-save-1")

    db.save_session(session)

    retrieved = db.get_session("sess-save-1")
    assert retrieved is not None
    assert retrieved.session_id == "sess-save-1"
    assert retrieved.status == ScanStatus.COMPLETED
    assert retrieved.summary.high_count == 1
    assert len(retrieved.findings) == 1

    f = retrieved.findings[0]
    assert f.finding_id == "find-test-1"
    assert f.category == OWASPCategory.API1_BOLA
    assert f.transaction is not None
    assert f.transaction.request_id == "req-test-1"
    assert f.transaction.response_status == 200


def test_list_sessions(tmp_path: Path) -> None:
    """Verify listing scan sessions with ordering and limits."""
    db_file = tmp_path / "test_apisec.db"
    db = DatabaseManager(db_file)

    s1 = _create_sample_session("sess-1")
    s2 = _create_sample_session("sess-2")
    db.save_session(s1)
    db.save_session(s2)

    sessions = db.list_sessions(limit=10)
    assert len(sessions) == 2
    session_ids = {s.session_id for s in sessions}
    assert "sess-1" in session_ids
    assert "sess-2" in session_ids


def test_delete_session_cascade(tmp_path: Path) -> None:
    """Verify deleting a session cascades to findings and transactions."""
    db_file = tmp_path / "test_apisec.db"
    db = DatabaseManager(db_file)
    session = _create_sample_session("sess-del-1")
    db.save_session(session)

    assert db.get_session("sess-del-1") is not None

    deleted = db.delete_session("sess-del-1")
    assert deleted is True
    assert db.get_session("sess-del-1") is None

    # Verify findings and transactions were also removed
    findings = db.get_findings_by_session("sess-del-1")
    assert len(findings) == 0


def test_get_nonexistent_session(tmp_path: Path) -> None:
    """Verify get_session returns None for missing sessions."""
    db_file = tmp_path / "test_apisec.db"
    db = DatabaseManager(db_file)
    assert db.get_session("non-existent") is None


def test_database_stats(tmp_path: Path) -> None:
    """Verify aggregated database metrics calculation."""
    db_file = tmp_path / "test_apisec.db"
    db = DatabaseManager(db_file)

    session = _create_sample_session("sess-stats-1")
    db.save_session(session)

    stats = db.get_stats()
    assert stats["total_sessions"] == 1
    assert stats["total_findings"] == 1
    assert stats["findings_by_severity"].get("HIGH") == 1
    assert stats["findings_by_category"].get(OWASPCategory.API1_BOLA.value) == 1
