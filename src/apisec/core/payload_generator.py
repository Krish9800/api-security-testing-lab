"""Intelligent test payload generator for API parameter fuzzing and boundary testing."""

from typing import Any

from apisec.models.spec import APIEndpoint


class PayloadGenerator:
    """Generates benign, boundary, and attack payloads for endpoint parameters and schemas."""

    # Common privilege escalation / mass assignment attributes
    MASS_ASSIGNMENT_PROBES: dict[str, Any] = {
        "role": "admin",
        "is_admin": True,
        "admin": True,
        "is_superuser": True,
        "permissions": ["all", "admin"],
        "account_balance": 1000000,
        "verified": True,
    }

    # SSRF probe URLs
    SSRF_PROBE_URLS: list[str] = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22",
        "http://localhost:8080/internal/status",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]

    # Extreme resource / pagination limits
    RESOURCE_LIMIT_PROBES: list[int] = [0, -1, 10000, 1000000, 2147483647]

    @classmethod
    def generate_mass_assignment_body(
        cls, base_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Merge malicious administrative attributes into request body."""
        body = dict(base_body or {"username": "tester", "email": "tester@example.com"})
        body.update(cls.MASS_ASSIGNMENT_PROBES)
        return body

    @classmethod
    def generate_fuzzed_parameters(cls, endpoint: APIEndpoint) -> list[dict[str, str]]:
        """Generate parameter variations testing boundaries and type confusion."""
        fuzzed_sets: list[dict[str, str]] = []

        path_or_query_params = [p for p in endpoint.parameters if p.location in ("path", "query")]
        if not path_or_query_params:
            return [{"id": "1"}, {"id": "2"}]

        # Normal test set
        normal: dict[str, str] = {}
        for p in path_or_query_params:
            normal[p.name] = "1" if p.param_type == "integer" else "test"
        fuzzed_sets.append(normal)

        # Extreme values / boundary set
        boundary: dict[str, str] = {}
        for p in path_or_query_params:
            if p.param_type == "integer":
                boundary[p.name] = "9999999"
            else:
                boundary[p.name] = "admin"
        fuzzed_sets.append(boundary)

        return fuzzed_sets
