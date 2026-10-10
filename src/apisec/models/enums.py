"""Domain enumerations for API security testing."""

from enum import StrEnum


class OWASPCategory(StrEnum):
    """OWASP API Security Top 10 (2023 edition) categories."""

    API1_BOLA = "API1:2023 Broken Object Level Authorization (BOLA)"
    API2_BROKEN_AUTH = "API2:2023 Broken Authentication"
    API3_BOPLA = "API3:2023 Broken Object Property Level Authorization"
    API4_UNRESTRICTED_RESOURCES = "API4:2023 Unrestricted Resource Consumption"
    API5_BFLA = "API5:2023 Broken Function Level Authorization (BFLA)"
    API6_SSRF = "API6:2023 Server-Side Request Forgery (SSRF)"
    API7_MISCONFIG = "API7:2023 Security Misconfiguration"
    API8_AUTOMATED_THREATS = "API8:2023 Lack of Protection from Automated Threats"
    API9_INVENTORY = "API9:2023 Improper Inventory Management"
    API10_UNSAFE_CONSUMPTION = "API10:2023 Unsafe Consumption of APIs"


class Severity(StrEnum):
    """Vulnerability severity rating."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class HTTPMethod(StrEnum):
    """Supported HTTP request methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class TestVerdict(StrEnum):
    """Outcome of a security test check."""

    __test__ = False

    PASS = "PASS"  # nosec B105
    VULNERABLE = "VULNERABLE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class ScanStatus(StrEnum):
    """Execution state of a scan session."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
