"""Executive Markdown vulnerability and session reporter."""

from pathlib import Path

from apisec.models.session import ScanSession


class MarkdownReporter:
    """Generates human-readable Markdown security assessment reports."""

    @staticmethod
    def generate(session: ScanSession) -> str:
        """Render a scan session as a formatted Markdown report."""
        lines: list[str] = [
            "# API Security Assessment Report",
            "",
            "## Scan Overview",
            "",
            f"- **Target Base URL:** `{session.target_base_url}`",
            f"- **Session ID:** `{session.session_id}`",
            f"- **Status:** `{session.status.value}`",
            f"- **Started At:** {session.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]
        if session.completed_at:
            lines.append(
                f"- **Completed At:** {session.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
        lines.extend(
            [
                "",
                "## Executive Summary",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Endpoints Tested | {session.summary.total_endpoints_tested} |",
                f"| Checks Executed | {session.summary.total_checks_executed} |",
                f"| Vulnerabilities Identified | {session.summary.vulnerabilities_found} |",
                f"| Critical Severity | {session.summary.critical_count} |",
                f"| High Severity | {session.summary.high_count} |",
                f"| Medium Severity | {session.summary.medium_count} |",
                f"| Low Severity | {session.summary.low_count} |",
                "",
                "## Vulnerability Findings",
                "",
            ]
        )

        if not session.findings:
            lines.append("No vulnerabilities identified during this security assessment run.")
            return "\n".join(lines)

        for i, f in enumerate(session.findings, start=1):
            lines.extend(
                [
                    f"### {i}. [{f.severity.value}] {f.title}",
                    "",
                    f"- **Category:** {f.category.value}",
                    f"- **Endpoint:** `{f.method.value} {f.endpoint}`",
                    f"- **CWE:** `{f.cwe_id or 'N/A'}`",
                    f"- **Verdict:** `{f.verdict.value}`",
                    "",
                    "#### Description",
                    f"{f.description}",
                    "",
                    "#### Evidence",
                    f"```text\n{f.evidence}\n```",
                    "",
                    "#### Remediation",
                    f"{f.remediation}",
                    "",
                ]
            )

            if f.transaction:
                tx = f.transaction
                lines.extend(
                    [
                        "#### Proof of Concept HTTP Exchange",
                        "",
                        f"- **Request ID:** `{tx.request_id}`",
                        f"- **URL:** `{tx.method.value} {tx.url}`",
                        f"- **Response Status:** `HTTP {tx.response_status}`",
                        f"- **Response Time:** `{tx.response_time_ms:.2f} ms`",
                        "",
                    ]
                )
                if tx.response_body:
                    sample = tx.response_body[:300]
                    lines.extend(
                        [
                            "```http",
                            f"HTTP/1.1 {tx.response_status}",
                            f"{sample}",
                            "```",
                            "",
                        ]
                    )

        return "\n".join(lines)

    @classmethod
    def save(cls, session: ScanSession, output_path: Path | str) -> Path:
        """Write Markdown report output to a file."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(session)
        target.write_text(content, encoding="utf-8")
        return target
