"""SQLite thread-safe database storage with WAL journal mode."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from apisec.config.settings import settings
from apisec.models.enums import HTTPMethod, OWASPCategory, ScanStatus, Severity, TestVerdict
from apisec.models.finding import HTTPTransaction, SecurityFinding
from apisec.models.session import ScanSession, ScanSummary


class DatabaseManager:
    """Manages SQLite storage for API security scan sessions and findings."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            self.db_path = settings.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def init_db(self) -> None:
        """Initialize database schema from schema.sql."""
        schema_path = Path(__file__).parent / "schema.sql"
        if not schema_path.exists():
            return
        with open(schema_path, encoding="utf-8") as f:
            schema_sql = f.read()
        with self._get_connection() as conn:
            conn.executescript(schema_sql)

    def save_session(self, session: ScanSession) -> None:
        """Persist or update a scan session and its associated findings."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scan_sessions (
                    session_id, target_base_url, status, started_at, completed_at,
                    total_endpoints, total_checks, vulnerabilities_found,
                    critical_count, high_count, medium_count, low_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    target_base_url = excluded.target_base_url,
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    total_endpoints = excluded.total_endpoints,
                    total_checks = excluded.total_checks,
                    vulnerabilities_found = excluded.vulnerabilities_found,
                    critical_count = excluded.critical_count,
                    high_count = excluded.high_count,
                    medium_count = excluded.medium_count,
                    low_count = excluded.low_count
                """,
                (
                    session.session_id,
                    session.target_base_url,
                    session.status.value,
                    session.started_at.isoformat(),
                    session.completed_at.isoformat() if session.completed_at else None,
                    session.summary.total_endpoints_tested,
                    session.summary.total_checks_executed,
                    session.summary.vulnerabilities_found,
                    session.summary.critical_count,
                    session.summary.high_count,
                    session.summary.medium_count,
                    session.summary.low_count,
                ),
            )
        if session.findings:
            self.save_findings(session.session_id, session.findings)

    def get_session(self, session_id: str) -> ScanSession | None:
        """Fetch a scan session by ID along with its findings."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scan_sessions WHERE session_id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            findings = self.get_findings_by_session(session_id)
            summary = ScanSummary(
                total_endpoints_tested=row["total_endpoints"],
                total_checks_executed=row["total_checks"],
                vulnerabilities_found=row["vulnerabilities_found"],
                critical_count=row["critical_count"],
                high_count=row["high_count"],
                medium_count=row["medium_count"],
                low_count=row["low_count"],
            )

            started_at = datetime.fromisoformat(row["started_at"])
            completed_at = (
                datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
            )

            return ScanSession(
                session_id=row["session_id"],
                target_base_url=row["target_base_url"],
                status=ScanStatus(row["status"]),
                started_at=started_at,
                completed_at=completed_at,
                findings=findings,
                summary=summary,
            )

    def list_sessions(self, limit: int = 50) -> list[ScanSession]:
        """List scan sessions ordered by started_at descending."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()

            sessions: list[ScanSession] = []
            for row in rows:
                summary = ScanSummary(
                    total_endpoints_tested=row["total_endpoints"],
                    total_checks_executed=row["total_checks"],
                    vulnerabilities_found=row["vulnerabilities_found"],
                    critical_count=row["critical_count"],
                    high_count=row["high_count"],
                    medium_count=row["medium_count"],
                    low_count=row["low_count"],
                )
                sessions.append(
                    ScanSession(
                        session_id=row["session_id"],
                        target_base_url=row["target_base_url"],
                        status=ScanStatus(row["status"]),
                        started_at=datetime.fromisoformat(row["started_at"]),
                        completed_at=(
                            datetime.fromisoformat(row["completed_at"])
                            if row["completed_at"]
                            else None
                        ),
                        findings=[],
                        summary=summary,
                    )
                )
            return sessions

    def delete_session(self, session_id: str) -> bool:
        """Delete a scan session and its cascaded records."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM scan_sessions WHERE session_id = ?",
                (session_id,),
            )
            return cursor.rowcount > 0

    def save_findings(self, session_id: str, findings: list[SecurityFinding]) -> None:
        """Save a list of findings and their HTTP transactions for a session."""
        with self._get_connection() as conn:
            for finding in findings:
                conn.execute(
                    """
                    INSERT INTO scan_findings (
                        finding_id, session_id, category, severity, title,
                        description, endpoint, method, verdict, evidence,
                        remediation, cwe_id, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        severity = excluded.severity,
                        evidence = excluded.evidence,
                        remediation = excluded.remediation
                    """,
                    (
                        finding.finding_id,
                        session_id,
                        finding.category.value,
                        finding.severity.value,
                        finding.title,
                        finding.description,
                        finding.endpoint,
                        finding.method.value,
                        finding.verdict.value,
                        finding.evidence,
                        finding.remediation,
                        finding.cwe_id,
                        finding.detected_at.isoformat(),
                    ),
                )

                if finding.transaction:
                    tx = finding.transaction
                    conn.execute(
                        """
                        INSERT INTO http_transactions (
                            request_id, finding_id, method, url, request_headers,
                            request_body, response_status, response_headers,
                            response_body, response_time_ms, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(request_id) DO UPDATE SET
                            response_status = excluded.response_status
                        """,
                        (
                            tx.request_id,
                            finding.finding_id,
                            tx.method.value,
                            tx.url,
                            json.dumps(tx.request_headers),
                            tx.request_body,
                            tx.response_status,
                            json.dumps(tx.response_headers),
                            tx.response_body,
                            tx.response_time_ms,
                            tx.timestamp.isoformat(),
                        ),
                    )

    def get_findings_by_session(self, session_id: str) -> list[SecurityFinding]:
        """Fetch all findings for a given scan session."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT f.*, t.request_id as tx_req_id, t.method as tx_method,
                       t.url as tx_url, t.request_headers as tx_req_headers,
                       t.request_body as tx_req_body, t.response_status as tx_resp_status,
                       t.response_headers as tx_resp_headers, t.response_body as tx_resp_body,
                       t.response_time_ms as tx_time_ms, t.timestamp as tx_timestamp
                FROM scan_findings f
                LEFT JOIN http_transactions t ON f.finding_id = t.finding_id
                WHERE f.session_id = ?
                ORDER BY f.detected_at ASC
                """,
                (session_id,),
            )
            rows = cursor.fetchall()

            findings: list[SecurityFinding] = []
            for r in rows:
                tx: HTTPTransaction | None = None
                if r["tx_req_id"]:
                    tx = HTTPTransaction(
                        request_id=r["tx_req_id"],
                        method=HTTPMethod(r["tx_method"]),
                        url=r["tx_url"],
                        request_headers=json.loads(r["tx_req_headers"]),
                        request_body=r["tx_req_body"],
                        response_status=r["tx_resp_status"],
                        response_headers=json.loads(r["tx_resp_headers"]),
                        response_body=r["tx_resp_body"],
                        response_time_ms=r["tx_time_ms"],
                        timestamp=datetime.fromisoformat(r["tx_timestamp"]),
                    )

                finding = SecurityFinding(
                    finding_id=r["finding_id"],
                    category=OWASPCategory(r["category"]),
                    severity=Severity(r["severity"]),
                    title=r["title"],
                    description=r["description"],
                    endpoint=r["endpoint"],
                    method=HTTPMethod(r["method"]),
                    verdict=TestVerdict(r["verdict"]),
                    evidence=r["evidence"],
                    remediation=r["remediation"],
                    cwe_id=r["cwe_id"],
                    transaction=tx,
                    detected_at=datetime.fromisoformat(r["detected_at"]),
                )
                findings.append(finding)
            return findings

    def get_stats(self) -> dict[str, Any]:
        """Aggregate summary metrics across all recorded scans."""
        with self._get_connection() as conn:
            total_sessions = conn.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM scan_findings").fetchone()[0]

            sev_cursor = conn.execute(
                "SELECT severity, COUNT(*) FROM scan_findings GROUP BY severity"
            )
            findings_by_severity = {row[0]: row[1] for row in sev_cursor.fetchall()}

            cat_cursor = conn.execute(
                "SELECT category, COUNT(*) FROM scan_findings GROUP BY category"
            )
            findings_by_category = {row[0]: row[1] for row in cat_cursor.fetchall()}

            return {
                "total_sessions": total_sessions,
                "total_findings": total_findings,
                "findings_by_severity": findings_by_severity,
                "findings_by_category": findings_by_category,
            }
