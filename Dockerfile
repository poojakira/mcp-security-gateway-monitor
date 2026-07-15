## Multi-stage build for MCP Security Gateway Monitor
## Stage 1: install dev dependencies, run tests, and build the release wheel
FROM python:3.11-slim AS builder

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY tests/ tests/
COPY deploy/ deploy/
COPY docker-compose.yml .
COPY locustfile.py .
COPY Dockerfile .

RUN pip install --no-cache-dir -e '.[dev]'
RUN python -m pytest tests/ -q --tb=short
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

## Stage 2: runtime image with only the built production package
FROM python:3.11-slim AS runtime

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && \
    rm -rf /wheels /root/.cache/pip

RUN useradd --create-home --shell /bin/bash appuser
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/v1/health')" || exit 1

CMD ["python", "-c", "from mcp_monitor.production.server import run_server; run_server()"]
