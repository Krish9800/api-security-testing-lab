"""OpenAPI 3.0 / 3.1 specification parser and endpoint extractor."""

import json
from pathlib import Path
from typing import Any

import httpx
import yaml

from apisec.core.exceptions import SpecParseError
from apisec.models.enums import HTTPMethod
from apisec.models.spec import APIEndpoint, APIParameter


class OpenAPIParser:
    """Parses OpenAPI 3.0 and 3.1 JSON/YAML definitions into structured APIEndpoints."""

    @classmethod
    def parse_text(cls, content: str) -> list[APIEndpoint]:
        """Parse raw JSON or YAML string into APIEndpoint models."""
        clean = content.strip()
        if not clean:
            raise SpecParseError("Empty OpenAPI specification document.")

        try:
            data = json.loads(clean) if clean.startswith("{") else yaml.safe_load(clean)
        except Exception as exc:
            raise SpecParseError(f"Failed to parse OpenAPI document: {exc}") from exc

        if not isinstance(data, dict):
            raise SpecParseError("OpenAPI root must be a dictionary.")

        return cls.parse_dict(data)

    @classmethod
    def parse_file(cls, file_path: Path | str) -> list[APIEndpoint]:
        """Read and parse OpenAPI specification from local filesystem."""
        path = Path(file_path)
        if not path.exists():
            raise SpecParseError(f"OpenAPI specification file not found: {path}")
        content = path.read_text(encoding="utf-8")
        return cls.parse_text(content)

    @classmethod
    def parse_url(cls, url: str, timeout: float = 10.0) -> list[APIEndpoint]:
        """Fetch and parse OpenAPI specification from remote URL."""
        try:
            with httpx.Client(timeout=timeout, verify=False) as client:  # nosec B501
                resp = client.get(url)
                resp.raise_for_status()
                return cls.parse_text(resp.text)
        except Exception as exc:
            raise SpecParseError(f"Failed to fetch remote OpenAPI spec from {url}: {exc}") from exc

    @classmethod
    def parse_dict(cls, data: dict[str, Any]) -> list[APIEndpoint]:
        """Decompose OpenAPI dictionary into APIEndpoints."""
        endpoints: list[APIEndpoint] = []
        paths = data.get("paths", {})
        if not isinstance(paths, dict):
            return endpoints

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method_str, op_item in path_item.items():
                if method_str.upper() not in [m.value for m in HTTPMethod]:
                    continue
                if not isinstance(op_item, dict):
                    continue

                method = HTTPMethod(method_str.upper())
                summary = op_item.get("summary", "")
                description = op_item.get("description", "")
                tags = op_item.get("tags", [])

                # Extract parameters (both path-level and operation-level)
                params: list[APIParameter] = []
                combined_params = path_item.get("parameters", []) + op_item.get("parameters", [])
                for p in combined_params:
                    if not isinstance(p, dict):
                        continue
                    p_name = p.get("name")
                    p_in = p.get("in", "query")
                    if not p_name:
                        continue
                    schema = p.get("schema", {})
                    p_type = schema.get("type", "string") if isinstance(schema, dict) else "string"
                    params.append(
                        APIParameter(
                            name=p_name,
                            location=p_in,
                            param_type=p_type,
                            required=p.get("required", False),
                            example=p.get("example"),
                        )
                    )

                # Check authentication requirements
                security = op_item.get("security", data.get("security", []))
                auth_required = bool(security)

                # Extract request body schema
                req_body = op_item.get("requestBody", {})
                content_map = req_body.get("content", {}) if isinstance(req_body, dict) else {}
                json_schema = None
                if "application/json" in content_map:
                    json_schema = content_map["application/json"].get("schema")

                endpoints.append(
                    APIEndpoint(
                        path=path_str,
                        method=method,
                        summary=summary,
                        description=description,
                        parameters=params,
                        request_body_schema=json_schema,
                        auth_required=auth_required,
                        tags=tags,
                    )
                )

        return endpoints
