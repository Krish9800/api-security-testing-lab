# Multi-stage rootless Dockerfile for APISec Testing Lab
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip wheel --no-cache-dir --no-deps -w /wheels .

# Runtime Stage
FROM python:3.12-slim AS runtime

WORKDIR /app

RUN groupadd -g 10001 apisec && \
    useradd -u 10001 -g apisec -s /bin/bash -m apisec

COPY pyproject.toml .
RUN pip install --no-cache-dir pip setuptools wheel && \
    pip install --no-cache-dir \
        fastapi \
        uvicorn \
        httpx \
        pydantic \
        pydantic-settings \
        pyyaml \
        typer \
        rich

COPY src /app/src
RUN pip install --no-cache-dir -e .

RUN mkdir -p /app/data && chown -R apisec:apisec /app

USER 10001

ENV PYTHONUNBUFFERED=1 \
    APISEC_DB_PATH=/app/data/apisec.db

EXPOSE 8000 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; res = httpx.get('http://127.0.0.1:8000/health'); exit(0 if res.status_code == 200 else 1)"

ENTRYPOINT ["apisec"]
CMD ["--help"]
