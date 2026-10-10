"""Base abstraction for OWASP API Security Top 10 vulnerability checks."""

from abc import ABC, abstractmethod

from apisec.core.http_client import SecurityHTTPClient
from apisec.models.enums import OWASPCategory, Severity
from apisec.models.finding import SecurityFinding
from apisec.models.session import ScanConfig
from apisec.models.spec import APIEndpoint


class BaseSecurityCheck(ABC):
    """Abstract interface defining an automated API security check."""

    category: OWASPCategory
    default_severity: Severity
    name: str
    description: str

    @abstractmethod
    def execute(
        self,
        endpoint: APIEndpoint,
        client: SecurityHTTPClient,
        config: ScanConfig,
    ) -> list[SecurityFinding]:
        """Execute vulnerability probe against endpoint and return findings."""
