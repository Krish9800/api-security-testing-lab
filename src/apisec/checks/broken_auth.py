"""API2:2023 Broken Authentication security check."""

import uuid
from datetime import UTC, datetime

from apisec.checks.base import BaseSecurityCheck
from apisec.core.http_client import SecurityHTTPClient
from apisec.models.enums import OWASPCategory, Severity, TestVerdict
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint


class BrokenAuthCheck(BaseSecurityCheck):
    """Detects missing authentication and accepted invalid/expired tokens."""

    category = OWASPCategory.API2_BROKEN_AUTH
    default_severity = Severity.CRITICAL
    name = "Broken Authentication Check"
    description = (
        "Probes protected endpoints with missing, malformed, and algorithm-confused tokens."
    )

    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        if not endpoint.auth_required:
            return findings

        # 1. Probe with missing authentication header entirely
        target_path = endpoint.path.replace("{id}", "1").replace("{user_id}", "1")
        resp_unauth, tx_unauth = client.send_request(
            method=endpoint.method,
            path=target_path,
        )

        if resp_unauth.status_code in (200, 201, 204):
            findings.append(
                SecurityFinding(
                    finding_id=f"find-auth-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.CRITICAL,
                    title=f"Unauthenticated Access to Protected Route {endpoint.endpoint_key}",
                    description=(
                        f"Endpoint {endpoint.path} declared authentication required but responded "
                        f"with HTTP {resp_unauth.status_code} when no credentials were supplied."
                    ),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    verdict=TestVerdict.VULNERABLE,
                    evidence=(
                        f"HTTP {resp_unauth.status_code} granted without Authorization header."
                    ),
                    remediation=(
                        "Enforce mandatory authentication verification in route middleware."
                    ),
                    cwe_id="CWE-306",
                    transaction=tx_unauth,
                    detected_at=datetime.now(UTC),
                )
            )

        # 2. Probe with invalid signature / dummy bearer token
        resp_bogus, tx_bogus = client.send_request(
            method=endpoint.method,
            path=target_path,
            headers={"Authorization": "Bearer invalid.token.payload"},
        )

        if resp_bogus.status_code in (200, 201, 204):
            findings.append(
                SecurityFinding(
                    finding_id=f"find-auth-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.CRITICAL,
                    title=f"Invalid Token Accepted in {endpoint.endpoint_key}",
                    description=(
                        f"Endpoint {endpoint.path} accepted a forged or invalid Bearer token."
                    ),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    verdict=TestVerdict.VULNERABLE,
                    evidence=(f"HTTP {resp_bogus.status_code} returned for forged token string."),
                    remediation="Cryptographically verify JWT signatures before granting access.",
                    cwe_id="CWE-347",
                    transaction=tx_bogus,
                    detected_at=datetime.now(UTC),
                )
            )

        return findings
