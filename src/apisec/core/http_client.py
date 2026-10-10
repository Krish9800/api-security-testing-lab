"""Resilient HTTP testing client with header redaction and transaction auditing."""

import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx

from apisec.config.settings import settings
from apisec.models.enums import HTTPMethod
from apisec.models.finding import HTTPTransaction


class SecurityHTTPClient:
    """Thread-safe HTTP client that audits transactions with credential redaction."""

    SENSITIVE_HEADERS = {"authorization", "x-api-key", "cookie", "set-cookie", "token"}

    def __init__(
        self,
        base_url: str = "",
        timeout: float | None = None,
        default_headers: dict[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout or settings.request_timeout_seconds
        self.default_headers = default_headers or {}

    def send_request(
        self,
        method: HTTPMethod,
        path: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
        data: Any | None = None,
    ) -> tuple[httpx.Response, HTTPTransaction]:
        """Execute HTTP request synchronously and record sanitized transaction audit log."""
        full_headers = dict(self.default_headers)
        if headers:
            full_headers.update(headers)

        full_url = f"{self.base_url}{path}" if path.startswith("/") else f"{self.base_url}/{path}"
        req_id = f"req-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)

        start_time = time.perf_counter()
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                verify=False,  # nosec B501
            ) as client:
                response = client.request(
                    method=method.value,
                    url=full_url,
                    headers=full_headers,
                    params=params,
                    json=json_data,
                    data=data,
                )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            resp_body = response.text
            resp_status = response.status_code
            resp_headers = dict(response.headers)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            resp_body = f"ERROR: {exc}"
            resp_status = 0
            resp_headers = {}
            # Create synthetic response for error conditions
            response = httpx.Response(
                status_code=500,
                request=httpx.Request(method.value, full_url),
                text=str(exc),
            )

        sanitized_req_headers = self._sanitize_headers(full_headers)
        sanitized_resp_headers = self._sanitize_headers(resp_headers)

        req_body_str = None
        if json_data is not None:
            import json

            req_body_str = json.dumps(json_data)
        elif data is not None:
            req_body_str = str(data)

        tx = HTTPTransaction(
            request_id=req_id,
            method=method,
            url=full_url,
            request_headers=sanitized_req_headers,
            request_body=req_body_str,
            response_status=resp_status,
            response_headers=sanitized_resp_headers,
            response_body=resp_body[:4096] if resp_body else None,  # Bounded for reporting
            response_time_ms=round(elapsed_ms, 2),
            timestamp=now,
        )

        return response, tx

    @classmethod
    def _sanitize_headers(cls, headers: dict[str, str]) -> dict[str, str]:
        """Redact tokens and credentials from logged headers."""
        sanitized: dict[str, str] = {}
        for k, v in headers.items():
            if k.lower() in cls.SENSITIVE_HEADERS:
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = v
        return sanitized
