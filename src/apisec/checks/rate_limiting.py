"""API4:2023 Unrestricted Resource Consumption (Rate Limiting) check."""

import uuid
from datetime import UTC, datetime

from apisec.checks.base import BaseSecurityCheck
from apisec.core.http_client import SecurityHTTPClient
from apisec.models.enums import OWASPCategory, Severity, TestVerdict
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint


class RateLimitingCheck(BaseSecurityCheck):
    """Detects lack of rate limiting and unrestricted resource consumption."""

    category = OWASPCategory.API4_UNRESTRICTED_RESOURCES
    default_severity = Severity.MEDIUM
    name = "Rate Limiting & Resource Consumption Check"
    description = "Fires high-frequency burst requests to verify rate limit enforcement."

    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        target_path = endpoint.path.replace("{id}", "1").replace("{user_id}", "1")
        burst_count = 15
        success_count = 0
        last_tx = None

        for _ in range(burst_count):
            resp, tx = client.send_request(method=endpoint.method, path=target_path)
            last_tx = tx
            if resp.status_code < 400:
                success_count += 1
            elif resp.status_code == 429:
                # Rate limit is properly enforced
                return []

        # If all 15 rapid requests succeeded without HTTP 429
        if success_count == burst_count and last_tx is not None:
            findings.append(
                SecurityFinding(
                    finding_id=f"find-rate-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=self.default_severity,
                    title=f"Missing Rate Limiting on {endpoint.endpoint_key}",
                    description=(
                        f"Endpoint {endpoint.path} executed {burst_count} rapid consecutive "
                        "requests without returning HTTP 429 Too Many Requests."
                    ),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    verdict=TestVerdict.VULNERABLE,
                    evidence=(
                        f"{burst_count}/{burst_count} rapid requests succeeded with status 200."
                    ),
                    remediation="Implement token-bucket or sliding-window rate limiting.",
                    cwe_id="CWE-770",
                    transaction=last_tx,
                    detected_at=datetime.now(UTC),
                )
            )

        return findings
