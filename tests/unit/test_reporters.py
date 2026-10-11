"""Unit tests for JSON, Markdown, and Rich report generators."""

import json
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from apisec.models.enums import HTTPMethod, OWASPCategory, ScanStatus, Severity, TestVerdict
from apisec.models.finding import HTTPTransaction, SecurityFinding
from apisec.models.session import ScanSession, ScanSummary
from apisec.reporters.json_reporter import JSONReporter
from apisec.reporters.markdown_reporter import MarkdownReporter
from apisec.reporters.rich_reporter import RichReporter


def _sample_session(has_findings: bool = True) -> ScanSession:
    tx = HTTPTransaction(
        request_id="req-rep-1",
        method=HTTPMethod.GET,
        url="http://test.api/users/2",
        request_headers={"Authorization": "Bearer tokenA"},
        request_body=None,
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body='{"id": 2, "user": "target"}',
        response_time_ms=18.5,
        timestamp=datetime.now(UTC),
    )
    findings = []
    if has_findings:
        findings.append(
            SecurityFinding(
                finding_id="find-rep-1",
                category=OWASPCategory.API1_BOLA,
                severity=Severity.HIGH,
                title="BOLA in GET /users/{id}",
                description="Cross-tenant access allowed without check.",
                endpoint="/users/{id}",
                method=HTTPMethod.GET,
                verdict=TestVerdict.VULNERABLE,
                evidence="HTTP 200 returned for id 2.",
                remediation="Enforce object-level authorization checks.",
                cwe_id="CWE-639",
                transaction=tx,
                detected_at=datetime.now(UTC),
            )
        )
    summary = ScanSummary(
        total_endpoints_tested=2,
        total_checks_executed=8,
        vulnerabilities_found=len(findings),
        critical_count=0,
        high_count=len(findings),
        medium_count=0,
        low_count=0,
    )
    return ScanSession(
        session_id="sess-rep-001",
        target_base_url="http://test.api",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        findings=findings,
        summary=summary,
    )


def test_json_reporter(tmp_path: Path) -> None:
    """Verify JSONReporter generates valid JSON and writes to disk."""
    session = _sample_session()
    json_str = JSONReporter.generate(session)
    parsed = json.loads(json_str)

    assert parsed["session_id"] == "sess-rep-001"
    assert parsed["summary"]["high_count"] == 1
    assert len(parsed["findings"]) == 1

    out_file = tmp_path / "report.json"
    saved = JSONReporter.save(session, out_file)
    assert saved.exists()
    assert json.loads(saved.read_text(encoding="utf-8"))["session_id"] == "sess-rep-001"


def test_markdown_reporter(tmp_path: Path) -> None:
    """Verify MarkdownReporter creates structured Markdown and writes to disk."""
    session = _sample_session()
    md_str = MarkdownReporter.generate(session)

    assert "# API Security Assessment Report" in md_str
    assert "BOLA in GET /users/{id}" in md_str
    assert "CWE-639" in md_str
    assert "Proof of Concept HTTP Exchange" in md_str

    out_file = tmp_path / "report.md"
    saved = MarkdownReporter.save(session, out_file)
    assert saved.exists()
    assert "## Executive Summary" in saved.read_text(encoding="utf-8")


def test_markdown_reporter_empty() -> None:
    """Verify MarkdownReporter handles clean sessions without findings."""
    session = _sample_session(has_findings=False)
    md_str = MarkdownReporter.generate(session)

    assert "No vulnerabilities identified" in md_str


def test_rich_reporter() -> None:
    """Verify RichReporter builds table and prints without error."""
    session = _sample_session()
    table = RichReporter.create_findings_table(session)
    assert table.row_count == 1

    console = Console(record=True)
    RichReporter.print_summary(session, console=console)
    output = console.export_text()

    assert "API Security Assessment Summary" in output
    assert "sess-rep-001" in output

    # Clean session
    clean_session = _sample_session(has_findings=False)
    RichReporter.print_summary(clean_session, console=console)
    clean_output = console.export_text()
    assert "No vulnerabilities detected" in clean_output
