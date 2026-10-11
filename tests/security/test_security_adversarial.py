"""Adversarial security tests for fuzzing, injection defense, and credential redaction."""

from pathlib import Path

import pytest

from apisec.core.exceptions import SpecParseError
from apisec.core.http_client import SecurityHTTPClient
from apisec.core.openapi_parser import OpenAPIParser
from apisec.db.database import DatabaseManager


def test_adversarial_header_redaction() -> None:
    """Verify that credentials in authorization and API key headers are masked in audit logs."""
    client = SecurityHTTPClient(base_url="http://test.api")
    headers = {
        "Authorization": "Bearer super-secret-jwt-token-12345",
        "X-API-Key": "my-ultra-secret-service-key",
        "Cookie": "session_id=confidential_session_value",
        "Custom-Header": "public-value",
    }
    sanitized = client._sanitize_headers(headers)

    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["X-API-Key"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["Custom-Header"] == "public-value"


def test_adversarial_malformed_openapi_fuzzing() -> None:
    """Verify OpenAPI parser robustly rejects adversarial input payloads."""
    fuzz_payloads = [
        "{'invalid_json': true}",
        "--- !python/object/apply:os.system ['echo hacked']",
        '{"openapi": 3, "paths": [1, 2, 3]}',
        "x" * 10000,
        "null",
        "true",
    ]
    for payload in fuzz_payloads:
        with pytest.raises(SpecParseError):
            OpenAPIParser.parse_text(payload)


def test_adversarial_sql_injection_defense(tmp_path: Path) -> None:
    """Verify parameterized SQLite queries neutralize SQL injection payloads."""
    db_file = tmp_path / "sqli_test.db"
    db = DatabaseManager(db_file)

    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE scan_sessions; --",
        "admin'--",
        "1' UNION SELECT 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12--",
    ]

    for payload in sqli_payloads:
        # None should succeed or alter database structure
        res = db.get_session(payload)
        assert res is None

        del_res = db.delete_session(payload)
        assert del_res is False

    # Check that table still exists and functions normally
    with db._get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]
        assert count == 0
