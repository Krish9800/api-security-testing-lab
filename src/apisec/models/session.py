"""Scan session and target profile models."""

from datetime import datetime

from pydantic import BaseModel, Field

from apisec.models.enums import ScanStatus
from apisec.models.finding import SecurityFinding


class ScanConfig(BaseModel):
    """Configuration options for an active API security scan run."""

    base_url: str
    auth_token_user_a: str | None = None
    auth_token_user_b: str | None = None
    admin_token: str | None = None
    active_categories: list[str] = Field(default_factory=list)
    rate_limit: float = 10.0
    timeout: float = 5.0


class ScanSummary(BaseModel):
    """Aggregate count metrics for a scan session."""

    total_endpoints_tested: int = 0
    total_checks_executed: int = 0
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class ScanSession(BaseModel):
    """Container tracking a full API security assessment session."""

    session_id: str
    target_base_url: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime
    completed_at: datetime | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: list[SecurityFinding] = Field(default_factory=list)
