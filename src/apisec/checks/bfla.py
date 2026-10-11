"""API5:2023 Broken Function Level Authorization (BFLA) security check."""

import uuid
from datetime import UTC, datetime

from apisec.checks.base import BaseSecurityCheck
from apisec.core.http_client import SecurityHTTPClient
from apisec.models.enums import OWASPCategory, Severity, TestVerdict
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint


class BFLACheck(BaseSecurityCheck):
    """Detects Broken Function Level Authorization (privilege escalation & admin access)."""

    category = OWASPCategory.API5_BFLA
    default_severity = Severity.HIGH
    name = "Broken Function Level Authorization Check"
    description = (
        "Probes administrative endpoints and privileged methods using unprivileged user tokens."
    )

    ADMIN_PATHS = ["/api/v1/admin/users", "/api/v1/admin/settings", "/admin"]

    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        is_admin_endpoint = "admin" in endpoint.path.lower() or "admin" in [
            t.lower() for t in endpoint.tags
        ]
        if not is_admin_endpoint:
            return findings

        # Test if regular user token A can access administrative functions
        user_token = config.auth_token_user_a
        headers = {"Authorization": f"Bearer {user_token}"} if user_token else {}

        target_path = endpoint.path.replace("{id}", "1").replace("{user_id}", "1")
        resp, tx = client.send_request(
            method=endpoint.method,
            path=target_path,
            headers=headers,
        )

        if resp.status_code in (200, 201, 204):
            findings.append(
                SecurityFinding(
                    finding_id=f"find-bfla-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"BFLA: Administrative Access Allowed in {endpoint.endpoint_key}",
                    description=(
                        f"Unprivileged standard user token was allowed to execute administrative "
                        f"endpoint {endpoint.path} without proper role-based authorization."
                    ),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    verdict=TestVerdict.VULNERABLE,
                    evidence=f"HTTP status {resp.status_code} granted to standard user token.",
                    remediation=(
                        "Enforce strict role-based access control (RBAC) on admin functions."
                    ),
                    cwe_id="CWE-285",
                    transaction=tx,
                    detected_at=datetime.now(UTC),
                )
            )

        return findings
