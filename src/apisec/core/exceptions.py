"""Custom domain exceptions for API Security Testing Lab."""


class APISecError(Exception):
    """Base exception for all apisec errors."""


class SpecParseError(APISecError):
    """Raised when an OpenAPI 3.0/3.1 or Postman collection fails to parse."""


class SecurityCheckError(APISecError):
    """Raised during security check execution failure."""


class DatabaseError(APISecError):
    """Raised on SQLite transaction or schema failure."""
