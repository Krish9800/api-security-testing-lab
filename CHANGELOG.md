# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-11

### Added
- **Core Security Engine:** Resilient `SecurityHTTPClient` with automatic sensitive header redaction (`Authorization`, `Cookie`, `X-API-Key`).
- **OpenAPI Parser:** Robust OpenAPI 3.0/3.1 parser supporting both JSON and YAML documents from files and remote URLs.
- **OWASP Check Suites:** Automated vulnerability detectors for BOLA (API1), Broken Authentication (API2), Mass Assignment (API3), Rate Limiting (API4), BFLA (API5), SSRF (API6), and CORS Misconfiguration (API7).
- **DvAPI Mock Lab:** Built-in intentionally vulnerable API testbed with 8 vulnerable endpoints for automated verification and training.
- **SQLite Storage:** Thread-safe SQLite persistence engine with WAL journal mode, cascade deletion, and audit trail indexing.
- **Multi-Format Reporters:** Structured JSON, executive Markdown, and interactive Rich console reporting.
- **Typer CLI:** Command-line interface with `scan`, `lab start`, `history`, `report`, and `stats` commands.
- **FastAPI Control Plane:** Full REST API control plane for orchestrating scans, managing histories, and viewing reports.
- **Containerization & CI:** Rootless multi-stage Dockerfile (UID 10001), Docker Compose deployment, and GitHub Actions CI workflow.
