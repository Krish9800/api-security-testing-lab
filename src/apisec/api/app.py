"""FastAPI REST control plane for orchestrating API security assessments."""

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel

from apisec.checks.runner import SecurityCheckRunner
from apisec.core.http_client import SecurityHTTPClient
from apisec.core.openapi_parser import OpenAPIParser
from apisec.db.database import DatabaseManager
from apisec.models.enums import HTTPMethod, ScanStatus, Severity
from apisec.models.session import ScanConfig, ScanSession, ScanSummary
from apisec.models.spec import APIEndpoint
from apisec.reporters.json_reporter import JSONReporter
from apisec.reporters.markdown_reporter import MarkdownReporter


class ScanInitiationRequest(BaseModel):
    """Payload to trigger an API security assessment."""

    target_url: str
    openapi_spec_url: str | None = None
    auth_token_user_a: str | None = None
    auth_token_user_b: str | None = None
    admin_token: str | None = None


def create_api_app() -> FastAPI:
    """Create and configure the APISec REST API application."""
    app = FastAPI(
        title="APISec Testing Lab Control Plane",
        version="1.0.0",
        description="REST API control plane for orchestrating OWASP API Top 10 security audits.",
    )

    db = DatabaseManager()

    @app.get("/health", tags=["System"])
    def health_check() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "ok", "version": "1.0.0"}

    @app.post(
        "/api/v1/scans",
        response_model=ScanSession,
        status_code=status.HTTP_201_CREATED,
        tags=["Scans"],
    )
    def trigger_scan(req: ScanInitiationRequest) -> ScanSession:
        """Execute an API security scan synchronously and record findings."""
        session_id = f"scan-{uuid.uuid4().hex[:8]}"
        start_time = datetime.now(UTC)

        client = SecurityHTTPClient(base_url=req.target_url)
        config = ScanConfig(
            base_url=req.target_url,
            auth_token_user_a=req.auth_token_user_a,
            auth_token_user_b=req.auth_token_user_b,
            admin_token=req.admin_token,
        )

        parser = OpenAPIParser()
        endpoints: list[APIEndpoint] = []

        if req.openapi_spec_url:
            try:
                endpoints = parser.parse_url(req.openapi_spec_url)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"Could not parse OpenAPI specification from {req.openapi_spec_url}: {exc}"
                    ),
                ) from exc
        else:
            try:
                endpoints = parser.parse_url(f"{req.target_url.rstrip('/')}/openapi.json")
            except Exception:
                # Fallback to standard probed routes
                endpoints = [
                    APIEndpoint(path="/api/v1/users/{id}", method=HTTPMethod.GET),
                    APIEndpoint(
                        path="/api/v1/protected/data",
                        method=HTTPMethod.GET,
                        auth_required=True,
                    ),
                    APIEndpoint(path="/api/v1/search", method=HTTPMethod.GET),
                ]

        runner = SecurityCheckRunner()
        findings = runner.run_all(endpoints, client, config)
        completed_time = datetime.now(UTC)

        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)

        summary = ScanSummary(
            total_endpoints_tested=len(endpoints),
            total_checks_executed=len(endpoints) * len(runner.checks),
            vulnerabilities_found=len(findings),
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
        )

        session = ScanSession(
            session_id=session_id,
            target_base_url=req.target_url,
            status=ScanStatus.COMPLETED,
            started_at=start_time,
            completed_at=completed_time,
            findings=findings,
            summary=summary,
        )

        db.save_session(session)
        return session

    @app.get("/api/v1/scans", response_model=list[ScanSession], tags=["Scans"])
    def list_scans(limit: int = Query(default=50, ge=1, le=100)) -> list[ScanSession]:
        """List historical scan sessions."""
        return db.list_sessions(limit=limit)

    @app.get("/api/v1/scans/{session_id}", response_model=ScanSession, tags=["Scans"])
    def get_scan(session_id: str) -> ScanSession:
        """Fetch details and findings of a specific scan session."""
        session = db.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan session '{session_id}' not found",
            )
        return session

    @app.get("/api/v1/scans/{session_id}/report", tags=["Scans"])
    def get_scan_report(
        session_id: str,
        report_format: str = Query(default="json", pattern="^(json|markdown)$"),
    ) -> Any:
        """Generate formatted assessment report in JSON or Markdown."""
        session = db.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan session '{session_id}' not found",
            )

        if report_format == "markdown":
            return {"format": "markdown", "content": MarkdownReporter.generate(session)}
        return JSONReporter.generate(session)

    @app.get("/api/v1/stats", tags=["System"])
    def get_stats() -> dict[str, Any]:
        """Aggregate security statistics across all recorded scans."""
        return db.get_stats()

    return app
