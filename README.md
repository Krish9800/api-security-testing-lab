# APISec: Automated OWASP API Security Testing Lab

[![Python Version](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type_checked-mypy-blue.svg)](https://mypy-lang.org/)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-green.svg)](https://github.com/PyCQA/bandit)
[![Test Coverage](https://img.shields.io/badge/coverage-90%25%2B-brightgreen.svg)](https://pytest.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

APISec is a production-grade, automated security testing framework and vulnerable mock laboratory (DvAPI) targeting the **OWASP API Security Top 10** vulnerabilities.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Interfaces["Interface Surfaces"]
        CLI["Typer CLI (apisec)"]
        REST["FastAPI Control Plane (:8000)"]
    end

    subgraph CoreEngine["APISec Security Engine"]
        Parser["OpenAPI 3.0/3.1 Parser"]
        PayloadGen["Fuzzing & Payload Generator"]
        Runner["SecurityCheckRunner"]
        HttpClient["Auditing SecurityHTTPClient"]
    end

    subgraph Checks["OWASP API Check Modules"]
        BOLA["API1: BOLA / IDOR"]
        AUTH["API2: Broken Authentication"]
        MASS["API3: Mass Assignment / BOPLA"]
        RATE["API4: Unrestricted Resource"]
        BFLA["API5: BFLA Admin Functions"]
        SSRF["API6: Server-Side Request Forgery"]
        CORS["API7: Security Misconfiguration"]
    end

    subgraph Storage["Storage & Reporting"]
        DB[(SQLite WAL Store)]
        JSONRep["JSON Reporter"]
        MDRep["Markdown Reporter"]
        RichRep["Rich Terminal UI"]
    end

    subgraph Lab["Built-in Target Lab"]
        DvAPI["DvAPI Mock API (:8888)"]
    end

    CLI --> Runner
    REST --> Runner
    Runner --> Parser
    Runner --> PayloadGen
    Runner --> Checks
    Checks --> HttpClient
    HttpClient --> DvAPI
    Runner --> DB
    DB --> JSONRep
    DB --> MDRep
    DB --> RichRep
```

---

## Features

- **OWASP API Top 10 Coverage:** Automated detection checks for BOLA, Broken Authentication, Mass Assignment, Rate Limiting, BFLA, SSRF, and CORS Misconfigurations.
- **OpenAPI 3.0 / 3.1 Parser:** Parses JSON and YAML specs from local files or remote endpoints.
- **Damn Vulnerable API (DvAPI):** Built-in mock API testbed with 8 vulnerable routes for offline testing and verification.
- **Resilient Auditing Client:** Captures full HTTP transaction traces with automatic credential redaction (`[REDACTED]`).
- **SQLite WAL Storage:** Thread-safe persistence with foreign key cascade deletion and indexing.
- **Multi-Format Reporting:** Generates machine-readable JSON, executive Markdown, and interactive Rich terminal tables.
- **Dual Interfaces:** Typer command-line interface and FastAPI REST control plane.
- **Hardened Rootless Container:** Multi-stage Docker build running under non-root UID 10001 (`apisec`).

---

## Quickstart

### 1. Installation

```bash
# Clone and set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Start the DvAPI Vulnerable Lab

```bash
apisec lab start --host 127.0.0.1 --port 8888
```

DvAPI documentation will be available at:
- Swagger UI: `http://127.0.0.1:8888/docs`
- OpenAPI Spec: `http://127.0.0.1:8888/openapi.json`

### 3. Run an Automated Security Assessment

```bash
apisec scan \
  --target http://127.0.0.1:8888 \
  --auth-a mock-token-alice \
  --auth-b mock-token-bob \
  --admin mock-token-admin \
  --out report.md \
  --format markdown
```

### 4. View Scan History & Stats

```bash
# View recent scans
apisec history

# View global vulnerability statistics
apisec stats
```

---

## REST Control Plane

To run the REST API control plane:

```bash
uvicorn apisec.api.app:create_api_app --factory --host 0.0.0.0 --port 8000
```

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status |
| `POST` | `/api/v1/scans` | Trigger an API security scan |
| `GET` | `/api/v1/scans` | List scan history |
| `GET` | `/api/v1/scans/{id}` | Get scan session details |
| `GET` | `/api/v1/scans/{id}/report` | Retrieve JSON or Markdown report |
| `GET` | `/api/v1/stats` | Aggregate vulnerability metrics |

---

## Docker Deployment

Run both the vulnerable mock lab and the scanner control plane using Docker Compose:

```bash
docker compose up -d
```

---

## Verification & Quality Gates

Run all quality gate checks to verify 100% adherence:

```bash
# Code formatting
ruff format --check src tests

# Static linting
ruff check src tests

# Static type checking
mypy src tests

# Security SAST audit
bandit -r src

# Unit and integration test suite with coverage
pytest --cov=src --cov-report=term-missing --cov-fail-under=90
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
