"""Data models representing HTTP transactions, findings, and proof of concept."""

from datetime import datetime

from pydantic import BaseModel, Field

from apisec.models.enums import HTTPMethod, OWASPCategory, Severity, TestVerdict


class HTTPTransaction(BaseModel):
    """Captured audit log of a single request and response exchange."""

    request_id: str
    method: HTTPMethod
    url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_status: int
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None
    response_time_ms: float
    timestamp: datetime


class SecurityFinding(BaseModel):
    """Identified API security vulnerability finding."""

    finding_id: str
    category: OWASPCategory
    severity: Severity
    title: str
    description: str
    endpoint: str
    method: HTTPMethod
    verdict: TestVerdict
    evidence: str
    remediation: str
    cwe_id: str = "CWE-200"
    transaction: HTTPTransaction | None = None
    detected_at: datetime
