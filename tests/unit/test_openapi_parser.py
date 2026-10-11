"""Unit tests for OpenAPI specification parser."""

from pathlib import Path

import pytest

from apisec.core.exceptions import SpecParseError
from apisec.core.openapi_parser import OpenAPIParser
from apisec.models.enums import HTTPMethod


def test_openapi_parser_json() -> None:
    """Verify parsing valid OpenAPI 3.0 JSON."""
    import json

    spec_dict = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users/{id}": {
                "get": {
                    "summary": "Get user",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "security": [{"bearerAuth": []}],
                },
                "put": {
                    "summary": "Update user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        }
                    },
                },
            }
        },
    }
    endpoints = OpenAPIParser.parse_text(json.dumps(spec_dict))
    assert len(endpoints) == 2

    get_ep = next(e for e in endpoints if e.method == HTTPMethod.GET)
    assert get_ep.path == "/users/{id}"
    assert get_ep.auth_required is True
    assert len(get_ep.parameters) == 1
    assert get_ep.parameters[0].name == "id"

    put_ep = next(e for e in endpoints if e.method == HTTPMethod.PUT)
    assert put_ep.request_body_schema is not None


def test_openapi_parser_yaml() -> None:
    """Verify parsing valid OpenAPI 3.0 YAML."""
    raw_yaml = """
openapi: 3.0.0
info:
  title: YAML API
  version: 1.0.0
paths:
  /orders:
    post:
      summary: Create order
      tags:
        - Orders
"""
    endpoints = OpenAPIParser.parse_text(raw_yaml)
    assert len(endpoints) == 1
    assert endpoints[0].path == "/orders"
    assert endpoints[0].method == HTTPMethod.POST
    assert "Orders" in endpoints[0].tags


def test_openapi_parser_malformed() -> None:
    """Verify parser raises SpecParseError on empty or invalid specifications."""
    with pytest.raises(SpecParseError):
        OpenAPIParser.parse_text("")

    with pytest.raises(SpecParseError):
        OpenAPIParser.parse_text("[]")


def test_openapi_parser_file(tmp_path: Path) -> None:
    """Verify parsing OpenAPI specification from filesystem path."""
    import json

    p = tmp_path / "spec.json"
    p.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "File API", "version": "1.0.0"},
                "paths": {"/ping": {"get": {"summary": "Ping"}}},
            }
        ),
        encoding="utf-8",
    )
    endpoints = OpenAPIParser.parse_file(p)
    assert len(endpoints) == 1
    assert endpoints[0].path == "/ping"

    with pytest.raises(SpecParseError):
        OpenAPIParser.parse_file(Path(str(tmp_path)) / "nonexistent.json")
