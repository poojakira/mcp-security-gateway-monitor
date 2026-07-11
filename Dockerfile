# Multi-stage build for MCP Security Gateway Monitor
# Stage 1: Builder - install dependencies and run tests
FROM python:3.11-slim AS builder

WORKDIR /app

# Copy all project files needed for build and tests
COPY pyproject.toml .
COPY src/ src/
COPY tests/ tests/
COPY deploy/ deploy/
COPY docker-compose.yml .
COPY locustfile.py .
COPY Dockerfile .

# Install package with dev dependencies and run tests
RUN pip install --no-cache-dir -e '.[dev]'
RUN python -m pytest tests/ -q --tb=short

# Stage 2: Runtime - minimal image with only production code
FROM python:3.11-slim AS runtime

WORKDIR /app

# Copy only what we need for production
COPY pyproject.toml .
COPY src/ src/

# Install production package (no dev dependencies)
RUN pip install --no-cache-dir . && \
    rm -rf /root/.cache/pip

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

EXPOSE 8080

# Healthcheck hitting the /v1/health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/v1/health')" || exit 1

# Run the production server
CMD ["python", "-c", "from mcp_monitor.production.server import run_server; run_server()"]
