"""Integration tests for Typer CLI commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from apisec.cli.main import app
from apisec.db.database import DatabaseManager

runner = CliRunner()


def test_cli_help() -> None:
    """Verify CLI help display."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "APISec - Automated OWASP API Security Testing" in result.output


def test_cli_stats() -> None:
    """Verify stats command runs and displays output."""
    result = runner.invoke(app, ["stats"])
    assert result.exit_code == 0
    assert "Database Assessment Statistics" in result.output


def test_cli_history() -> None:
    """Verify history command runs."""
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0


def test_cli_scan_with_local_spec(tmp_path: Path) -> None:
    """Verify scan command using local OpenAPI spec file."""
    # Create sample spec file
    spec_data = {
        "openapi": "3.0.0",
        "info": {"title": "Sample API", "version": "1.0.0"},
        "paths": {
            "/api/v1/users/{id}": {
                "get": {
                    "summary": "Get user",
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    spec_file = tmp_path / "test_spec.json"
    spec_file.write_text(json.dumps(spec_data), encoding="utf-8")

    out_file = tmp_path / "scan_report.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "http://test.api",
            "--spec",
            str(spec_file),
            "--out",
            str(out_file),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    report_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert report_data["target_base_url"] == "http://test.api"


def test_cli_report_command(tmp_path: Path) -> None:
    """Verify report retrieval command."""
    db = DatabaseManager()
    sessions = db.list_sessions(limit=1)
    if sessions:
        session_id = sessions[0].session_id
        res_rich = runner.invoke(app, ["report", "--session-id", session_id])
        assert res_rich.exit_code == 0

        # Export JSON
        out_json = tmp_path / "exported.json"
        res_json = runner.invoke(
            app,
            [
                "report",
                "--session-id",
                session_id,
                "--format",
                "json",
                "--out",
                str(out_json),
            ],
        )
        assert res_json.exit_code == 0
        assert out_json.exists()

    # Missing session
    res_missing = runner.invoke(app, ["report", "--session-id", "non-existent-id"])
    assert res_missing.exit_code == 1


def test_cli_scan_fallback_and_markdown(tmp_path: Path) -> None:
    """Verify scan command fallback probing and markdown export."""
    out_md = tmp_path / "scan_report.md"
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "http://127.0.0.1:9999",
            "--out",
            str(out_md),
            "--format",
            "markdown",
        ],
    )
    assert result.exit_code == 0
    assert out_md.exists()
    assert "# API Security Assessment Report" in out_md.read_text(encoding="utf-8")

    # Verify history now lists recorded sessions
    res_hist = runner.invoke(app, ["history"])
    assert res_hist.exit_code == 0
    assert "Assessment Scan History" in res_hist.output

    # Verify report in markdown
    db = DatabaseManager()
    sessions = db.list_sessions(limit=1)
    if sessions:
        res_rep_md = runner.invoke(
            app, ["report", "--session-id", sessions[0].session_id, "--format", "markdown"]
        )
        assert res_rep_md.exit_code == 0
        assert "# API Security Assessment Report" in res_rep_md.output
