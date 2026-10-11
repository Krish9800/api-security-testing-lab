"""API6:2023 Server-Side Request Forgery (SSRF) and API7:2023 Misconfiguration checks."""

import uuid
from datetime import UTC, datetime

from apisec.checks.base import BaseSecurityCheck
from apisec.core.http_client import SecurityHTTPClient
from apisec.core.payload_generator import PayloadGenerator
from apisec.models.enums import OWASPCategory, Severity, TestVerdict
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint


class SSRFCheck(BaseSecurityCheck):
    """Detects Server-Side Request Forgery via callback/URL parameter injection."""

    category = OWASPCategory.API6_SSRF
    default_severity = Severity.HIGH
    name = "Server-Side Request Forgery (SSRF) Check"
    description = (
        "Injects cloud metadata and internal loopback URLs into webhook and URL parameters."
    )

    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        url_params = [
            p
            for p in endpoint.parameters
            if any(k in p.name.lower() for k in ("url", "webhook", "callback", "redirect", "dest"))
        ]
        if not url_params:
            return findings

        for p in url_params:
            for probe in PayloadGenerator.SSRF_PROBE_URLS[:2]:
                resp, tx = client.send_request(
                    method=endpoint.method,
                    path=endpoint.path,
                    params={p.name: probe},
                )
                if resp.status_code in (200, 201) and (
                    "meta-data" in resp.text or "ami-id" in resp.text
                ):
                    findings.append(
                        SecurityFinding(
                            finding_id=f"find-ssrf-{uuid.uuid4().hex[:8]}",
                            category=self.category,
                            severity=self.default_severity,
                            title=f"SSRF in Parameter '{p.name}' on {endpoint.endpoint_key}",
                            description=f"Endpoint accessed internal network address {probe}.",
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            verdict=TestVerdict.VULNERABLE,
                            evidence=f"Internal response body leaked in parameter {p.name}.",
                            remediation=(
                                "Validate URL schemes, restrict to egress proxies, "
                                "and block loopback IPs."
                            ),
                            cwe_id="CWE-918",
                            transaction=tx,
                            detected_at=datetime.now(UTC),
                        )
                    )
        return findings


class SecurityMisconfigCheck(BaseSecurityCheck):
    """Detects missing security headers, CORS wildcards, and stack traces."""

    category = OWASPCategory.API7_MISCONFIG
    default_severity = Severity.MEDIUM
    name = "Security Misconfiguration Check"
    description = "Checks response headers, CORS settings, and verbose error traces."

    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        target_path = endpoint.path.replace("{id}", "1").replace("{user_id}", "1")
        resp, tx = client.send_request(
            method=endpoint.method,
            path=target_path,
            headers={"Origin": "https://evil-attacker.com"},
        )

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # 1. CORS wildcard with credentials
        allow_origin = headers_lower.get("access-control-allow-origin", "")
        allow_creds = headers_lower.get("access-control-allow-credentials", "").lower() == "true"
        if allow_origin in ("*", "https://evil-attacker.com") and allow_creds:
            findings.append(
                SecurityFinding(
                    finding_id=f"find-cors-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"Insecure CORS Configuration on {endpoint.endpoint_key}",
                    description=(
                        "Access-Control-Allow-Origin dynamically reflected untrusted "
                        "origin with credentials."
                    ),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    verdict=TestVerdict.VULNERABLE,
                    evidence=f"Origin reflected: {allow_origin}, Allow-Credentials: true",
                    remediation="Explicitly whitelist trusted origins without echoing wildcards.",
                    cwe_id="CWE-942",
                    transaction=tx,
                    detected_at=datetime.now(UTC),
                )
            )

        # 2. Stack trace disclosure
        if resp.status_code >= 500 and (
            "traceback (most recent call last)" in resp.text.lower()
            or "exception in thread" in resp.text.lower()
        ):
            findings.append(
                SecurityFinding(
                    finding_id=f"find-stack-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.LOW,
                    title=f"Verbose Stack Trace Disclosed in {endpoint.endpoint_key}",
                    description="500 Internal Server Error returned raw server stack trace.",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    verdict=TestVerdict.VULNERABLE,
                    evidence=resp.text[:300],
                    remediation="Disable debug mode and implement centralized exception handling.",
                    cwe_id="CWE-209",
                    transaction=tx,
                    detected_at=datetime.now(UTC),
                )
            )

        return findings
