"""Data models representing parsed API endpoints, parameters, and schemas."""

from typing import Any

from pydantic import BaseModel, Field

from apisec.models.enums import HTTPMethod


class APIParameter(BaseModel):
    """Specification of a query, path, or header parameter."""

    name: str
    location: str = Field(description="'query', 'path', or 'header'")
    param_type: str = "string"
    required: bool = False
    default: Any | None = None
    example: Any | None = None


class APIEndpoint(BaseModel):
    """Discovered or parsed API endpoint route definition."""

    path: str
    method: HTTPMethod
    summary: str = ""
    description: str = ""
    parameters: list[APIParameter] = Field(default_factory=list)
    request_body_schema: dict[str, Any] | None = None
    auth_required: bool = False
    tags: list[str] = Field(default_factory=list)

    @property
    def endpoint_key(self) -> str:
        """Unique key identifying the method and path."""
        return f"{self.method.value} {self.path}"
