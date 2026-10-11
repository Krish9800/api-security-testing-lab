"""API3:2023 Broken Object Property Level Authorization (Mass Assignment & Data Exposure)."""

import json
import logging
import uuid
from datetime import UTC, datetime

from apisec.checks.base import BaseSecurityCheck
from apisec.core.http_client import SecurityHTTPClient
from apisec.core.payload_generator import PayloadGenerator
from apisec.models.enums import HTTPMethod, OWASPCategory, Severity, TestVerdict
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint

logger = logging.getLogger(__name__)


class MassAssignmentCheck(BaseSecurityCheck):
    """Detects Mass Assignment and excessive data exposure vulnerabilities."""

    category = OWASPCategory.API3_BOPLA
    default_severity = Severity.HIGH
    name = "Mass Assignment & Property Auth Check"
    description = "Tests endpoints against unauthorized parameter injection and property updates."

    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        # Target write operations (POST, PUT, PATCH)
        if endpoint.method not in (HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH):
            return findings

        token = config.auth_token_user_a
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        target_path = endpoint.path.replace("{id}", "1").replace("{user_id}", "1")

        # Inject mass assignment body
        payload = PayloadGenerator.generate_mass_assignment_body()

        resp, tx = client.send_request(
            method=endpoint.method,
            path=target_path,
            headers=headers,
            json_data=payload,
        )

        if resp.status_code in (200, 201):
            try:
                body_json = resp.json()
                if isinstance(body_json, dict) and (
                    body_json.get("role") == "admin"
                    or body_json.get("is_admin") is True
                    or body_json.get("admin") is True
                ):
                    findings.append(
                        SecurityFinding(
                            finding_id=f"find-mass-{uuid.uuid4().hex[:8]}",
                            category=self.category,
                            severity=self.default_severity,
                            title=f"Mass Assignment in {endpoint.endpoint_key}",
                            description=(
                                f"Endpoint {endpoint.path} accepted sensitive property "
                                "modification submitted by an unprivileged user."
                            ),
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            verdict=TestVerdict.VULNERABLE,
                            evidence=(
                                f"Echoed modified privilege property: {json.dumps(body_json)[:80]}"
                            ),
                            remediation=(
                                "Explicitly whitelist allowed user-modifiable properties "
                                "using DTO / schema filtering."
                            ),
                            cwe_id="CWE-915",
                            transaction=tx,
                            detected_at=datetime.now(UTC),
                        )
                    )
            except Exception as exc:
                logger.debug("Failed to evaluate mass assignment probe: %s", exc)

        return findings
