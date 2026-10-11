"""Typer CLI interface for API Security Testing Lab."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from apisec.checks.runner import SecurityCheckRunner
from apisec.core.http_client import SecurityHTTPClient
from apisec.core.openapi_parser import OpenAPIParser
from apisec.db.database import DatabaseManager
from apisec.lab.dvapi import create_dvapi_app
from apisec.models.enums import HTTPMethod, ScanStatus, Severity
from apisec.models.session import ScanConfig, ScanSession, ScanSummary
from apisec.models.spec import APIEndpoint
from apisec.reporters.json_reporter import JSONReporter
from apisec.reporters.markdown_reporter import MarkdownReporter
from apisec.reporters.rich_reporter import RichReporter

app = typer.Typer(
    name="apisec",
    help="APISec - Automated OWASP API Security Testing CLI & Vulnerable Lab",
    no_args_is_help=True,
)
lab_app = typer.Typer(name="lab", help="Manage built-in vulnerable API testbed (DvAPI)")
app.add_typer(lab_app)

console = Console()


@app.command(name="scan")
def scan_command(
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Target API base URL"),
    ] = "http://localhost:8888",
    spec: Annotated[
        str | None,
        typer.Option("--spec", "-s", help="Path or URL to OpenAPI specification"),
    ] = None,
    auth_a: Annotated[
        str | None,
        typer.Option("--auth-a", help="Bearer authentication token for User A"),
    ] = None,
    auth_b: Annotated[
        str | None,
        typer.Option("--auth-b", help="Bearer authentication token for User B"),
    ] = None,
    admin_token: Annotated[
        str | None,
        typer.Option("--admin", help="Bearer authentication token for Admin user"),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Output report file destination"),
    ] = None,
    format_type: Annotated[
        str,
        typer.Option("--format", "-f", help="Report format (rich, json, markdown)"),
    ] = "rich",
) -> None:
    """Execute an automated OWASP API Top 10 security scan against a target API."""
    db = DatabaseManager()
    session_id = f"scan-{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(UTC)

    console.print(f"[bold cyan]Initiating API security scan against:[/bold cyan] {target}")

    client = SecurityHTTPClient(base_url=target)
    config = ScanConfig(
        base_url=target,
        auth_token_user_a=auth_a,
        auth_token_user_b=auth_b,
        admin_token=admin_token,
    )

    parser = OpenAPIParser()
    endpoints: list[APIEndpoint] = []

    if spec:
        spec_path = Path(spec)
        endpoints = parser.parse_file(spec_path) if spec_path.exists() else parser.parse_url(spec)
    else:
        # Attempt to auto-fetch openapi.json from standard target location
        try:
            endpoints = parser.parse_url(f"{target.rstrip('/')}/openapi.json")
        except Exception:
            console.print(
                "[yellow]Could not fetch /openapi.json. Using standard route probing.[/yellow]"
            )
            # Default fallback endpoints
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

    # Compute summary counts
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
        target_base_url=target,
        status=ScanStatus.COMPLETED,
        started_at=start_time,
        completed_at=completed_time,
        findings=findings,
        summary=summary,
    )

    db.save_session(session)

    # Display console output
    RichReporter.print_summary(session, console=console)

    if out:
        fmt = format_type.lower()
        if fmt == "json":
            JSONReporter.save(session, out)
            console.print(f"[bold green]Report saved to JSON:[/bold green] {out}")
        elif fmt == "markdown":
            MarkdownReporter.save(session, out)
            console.print(f"[bold green]Report saved to Markdown:[/bold green] {out}")
        else:
            MarkdownReporter.save(session, out)
            console.print(f"[bold green]Report saved:[/bold green] {out}")


@lab_app.command(name="start")
def lab_start_command(
    host: Annotated[str, typer.Option("--host", help="Binding host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Binding port")] = 8888,
) -> None:
    """Launch the built-in DvAPI intentionally vulnerable mock API laboratory."""
    import uvicorn

    console.print(
        Panel(
            f"[bold green]Starting DvAPI Vulnerable API Lab on http://{host}:{port}[/bold green]\n"
            f"[cyan]OpenAPI documentation:[/cyan] http://{host}:{port}/docs\n"
            f"[cyan]OpenAPI specification:[/cyan] http://{host}:{port}/openapi.json",
            title="DvAPI Laboratory",
            border_style="green",
        )
    )
    app_instance = create_dvapi_app()
    uvicorn.run(app_instance, host=host, port=port)


@app.command(name="history")
def history_command(
    limit: Annotated[int, typer.Option("--limit", "-n", help="Number of records to display")] = 20,
) -> None:
    """Display recent security assessment scan history from SQLite database."""
    db = DatabaseManager()
    sessions = db.list_sessions(limit=limit)

    if not sessions:
        console.print("[yellow]No assessment history found in database.[/yellow]")
        return

    table = Table(title="Assessment Scan History", header_style="bold cyan")
    table.add_column("Session ID", style="bold", width=16)
    table.add_column("Target URL", width=28)
    table.add_column("Status", width=12)
    table.add_column("Endpoints", width=10)
    table.add_column("Findings", width=10)
    table.add_column("Started At", width=22)

    for s in sessions:
        table.add_row(
            s.session_id,
            s.target_base_url,
            s.status.value,
            str(s.summary.total_endpoints_tested),
            str(s.summary.vulnerabilities_found),
            s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print(table)


@app.command(name="report")
def report_command(
    session_id: Annotated[str, typer.Option("--session-id", "-i", help="Scan session identifier")],
    format_type: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: rich, json, markdown"),
    ] = "rich",
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Output file destination"),
    ] = None,
) -> None:
    """Export or view a historical security assessment report."""
    db = DatabaseManager()
    session = db.get_session(session_id)

    if not session:
        console.print(f"[bold red]Session '{session_id}' not found.[/bold red]")
        raise typer.Exit(code=1)

    fmt = format_type.lower()
    if fmt == "json":
        json_output = JSONReporter.generate(session)
        if out:
            JSONReporter.save(session, out)
            console.print(f"[green]Saved JSON report to {out}[/green]")
        else:
            console.print(json_output)
    elif fmt == "markdown":
        md_output = MarkdownReporter.generate(session)
        if out:
            MarkdownReporter.save(session, out)
            console.print(f"[green]Saved Markdown report to {out}[/green]")
        else:
            console.print(md_output)
    else:
        RichReporter.print_summary(session, console=console)


@app.command(name="stats")
def stats_command() -> None:
    """Display aggregate metrics across all historical API security scans."""
    db = DatabaseManager()
    stats = db.get_stats()

    overview = (
        f"[bold]Total Scans Recorded:[/bold] {stats['total_sessions']}\n"
        f"[bold]Total Vulnerabilities Found:[/bold] {stats['total_findings']}\n\n"
        f"[bold]Severity Breakdown:[/bold]\n"
        + "\n".join(
            f"  - {sev}: {cnt}" for sev, cnt in stats.get("findings_by_severity", {}).items()
        )
    )

    console.print(Panel(overview, title="Database Assessment Statistics", border_style="cyan"))


if __name__ == "__main__":
    app()
