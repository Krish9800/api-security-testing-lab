"""Terminal interactive reporter using Rich tables and formatting."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from apisec.models.enums import Severity
from apisec.models.session import ScanSession


class RichReporter:
    """Renders formatted terminal summaries using Rich."""

    SEVERITY_STYLES: dict[Severity, str] = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold magenta",
        Severity.MEDIUM: "bold yellow",
        Severity.LOW: "bold cyan",
        Severity.INFO: "bold green",
    }

    @classmethod
    def create_findings_table(cls, session: ScanSession) -> Table:
        """Construct a formatted Rich Table of security findings."""
        table = Table(
            title=f"Assessment Findings: {session.target_base_url}",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Category", width=16)
        table.add_column("Method", width=8)
        table.add_column("Endpoint", width=30)
        table.add_column("Title", style="white")
        table.add_column("CWE", width=10)

        for f in session.findings:
            sev_style = cls.SEVERITY_STYLES.get(f.severity, "white")
            cat_short = (
                f.category.value.split(":")[0] if ":" in f.category.value else f.category.value
            )
            table.add_row(
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                cat_short,
                f.method.value,
                f.endpoint,
                f.title,
                f.cwe_id or "N/A",
            )
        return table

    @classmethod
    def print_summary(cls, session: ScanSession, console: Console | None = None) -> None:
        """Print full styled overview and findings table to the console."""
        con = console or Console()

        overview_text = (
            f"[bold]Target Base URL:[/bold] {session.target_base_url}\n"
            f"[bold]Session ID:[/bold] {session.session_id}\n"
            f"[bold]Status:[/bold] {session.status.value}\n"
            f"[bold]Endpoints Tested:[/bold] {session.summary.total_endpoints_tested} | "
            f"[bold]Checks Run:[/bold] {session.summary.total_checks_executed}\n"
            f"[bold red]Critical: {session.summary.critical_count}[/] | "
            f"[bold magenta]High: {session.summary.high_count}[/] | "
            f"[bold yellow]Medium: {session.summary.medium_count}[/] | "
            f"[bold cyan]Low: {session.summary.low_count}[/]"
        )

        con.print(
            Panel(
                overview_text,
                title="API Security Assessment Summary",
                border_style="cyan",
            )
        )

        if session.findings:
            table = cls.create_findings_table(session)
            con.print(table)
        else:
            con.print("[bold green]✓ No vulnerabilities detected in tested routes.[/bold green]")
