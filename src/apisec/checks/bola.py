"""API1:2023 Broken Object Level Authorization (BOLA/IDOR) security check."""

import uuid
from datetime import UTC, datetime

from apisec.checks.base import BaseSecurityCheck
from apisec.core.http_client import SecurityHTTPClient
from apisec.models.enums import OWASPCategory, Severity, TestVerdict
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint


class BOLACheck(BaseSecurityCheck):
    """Detects Broken Object Level Authorization (IDOR) via dual-token swapping."""

    category = OWASPCategory.API1_BOLA
    default_severity = Severity.HIGH
    name = "BOLA / IDOR Authorization Check"
    description = (
        "Attempts cross-tenant access to object identifiers using disparate user sessions."
    )

    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        # Only check endpoints containing path parameters (e.g., /users/{id})
        path_params = [p for p in endpoint.parameters if p.location == "path"]
        if not path_params:
            return findings

        # Requires two test user tokens to test cross-tenant object access
        if not config.auth_token_user_a or not config.auth_token_user_b:
            return findings

        # Substitute object identifier for User B's resource
        target_path = endpoint.path
        for p in path_params:
            target_path = target_path.replace(f"{{{p.name}}}", "2")

        # Request resource belonging to User B using User A's token
        headers_user_a = {"Authorization": f"Bearer {config.auth_token_user_a}"}
        resp, tx = client.send_request(
            method=endpoint.method,
            path=target_path,
            headers=headers_user_a,
        )

        # Vulnerable if User A successfully receives 200 OK for User B's object
        if resp.status_code == 200 and ("user" in resp.text.lower() or "id" in resp.text.lower()):
            findings.append(
                SecurityFinding(
                    finding_id=f"find-bola-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=self.default_severity,
                    title=f"BOLA / IDOR in {endpoint.endpoint_key}",
                    description=(
                        f"Endpoint {endpoint.path} allowed User A to read or manipulate "
                        "User B's object without proper object-level authorization validation."
                    ),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    verdict=TestVerdict.VULNERABLE,
                    evidence=(
                        f"HTTP status {resp.status_code} returned for cross-tenant object query: "
                        f"{target_path}"
                    ),
                    remediation=(
                        "Validate that the authenticated user owns or has explicit permission "
                        "to access the requested object ID before returning data."
                    ),
                    cwe_id="CWE-639",
                    transaction=tx,
                    detected_at=datetime.now(UTC),
                )
            )

        return findings
