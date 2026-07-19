# MCP Security Gateway Monitor - Production Dockerfile
FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Run tests in builder stage
RUN pip install --no-cache-dir pytest
RUN pip install --no-cache-dir -e .
RUN pytest tests/ -v

# Build wheel for runtime
RUN pip wheel --wheel-dir=/wheels --no-deps .
RUN pip install --no-cache-dir /wheels/*.whl

# Production stage
FROM python:3.11-slim as runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

# Copy wheel from builder and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl

# Copy MCP monitor source
COPY src/mcp_monitor ./mcp_monitor
COPY pyproject.toml .
COPY README.md .

# Non-root user
RUN groupadd -r mlsec && useradd -r -g mlsec mlsec
RUN chown -R mlsec:mlsec /app
USER mlsec

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/v1/health || exit 1

CMD ["python", "-m", "mcp_monitor.monitor", "--help"]