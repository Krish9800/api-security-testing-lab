"""Security check runner orchestrating all OWASP API tests."""

import logging

from apisec.checks.base import BaseSecurityCheck
from apisec.checks.bfla import BFLACheck
from apisec.checks.bola import BOLACheck
from apisec.checks.broken_auth import BrokenAuthCheck
from apisec.checks.mass_assignment import MassAssignmentCheck
from apisec.checks.misconfig import SecurityMisconfigCheck, SSRFCheck
from apisec.checks.rate_limiting import RateLimitingCheck
from apisec.core.http_client import SecurityHTTPClient
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint

logger = logging.getLogger(__name__)


class SecurityCheckRunner:
    """Orchestrates security checks across parsed endpoints."""

    def __init__(self, checks: list[BaseSecurityCheck] | None = None) -> None:
        self.checks: list[BaseSecurityCheck] = checks or [
            BOLACheck(),
            BrokenAuthCheck(),
            MassAssignmentCheck(),
            RateLimitingCheck(),
            BFLACheck(),
            SSRFCheck(),
            SecurityMisconfigCheck(),
        ]

    def run_all(
        self,
        endpoints: list[APIEndpoint],
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        """Execute all configured checks across all endpoints."""
        all_findings: list[SecurityFinding] = []

        for endpoint in endpoints:
            for check in self.checks:
                try:
                    findings = check.execute(endpoint, client, config)
                    all_findings.extend(findings)
                except Exception as exc:
                    logger.warning(
                        "Check %s failed on endpoint %s: %s",
                        check.name,
                        endpoint.endpoint_key,
                        exc,
                    )

        return all_findings
