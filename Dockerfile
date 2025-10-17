# Multi-stage Dockerfile for inbound-parsers
# Stage 1: Build Bento binary
FROM golang:1.21-alpine AS bento-builder
WORKDIR /build
RUN apk add --no-cache git make
RUN git clone --depth 1 --branch v1.0.0 https://github.com/warpstreamlabs/bento.git
WORKDIR /build/bento
RUN CGO_ENABLED=0 go build -o bento ./cmd/bento

# Stage 2: Python dependencies
FROM python:3.11-slim AS python-builder
WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry==1.7.1

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies (no dev deps in production)
RUN poetry config virtualenvs.in-project true && \
    poetry install --no-root --no-dev --no-interaction --no-ansi

# Stage 3: Runtime image
FROM python:3.11-slim AS runtime

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Bento binary from builder
COPY --from=bento-builder /build/bento/bento /usr/local/bin/bento

# Copy Python virtual environment from builder
COPY --from=python-builder /app/.venv /app/.venv

# Copy application code
COPY parsers/ ./parsers/
COPY workers/ ./workers/
COPY bento/ ./bento/

# Environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app" \
    PYTHONUNBUFFERED=1 \
    PIPELINE="fbl"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:4195/ping || exit 1

# Default command runs Bento with specified pipeline
CMD ["sh", "-c", "bento run /app/bento/${PIPELINE}.yaml"]

# Stage 4: Development image (with hot reload)
FROM runtime AS development

# Install dev dependencies
RUN pip install --no-cache-dir watchdog[watchmedo]

# Override for development
CMD ["sh", "-c", "watchmedo auto-restart --directory=/app --pattern=*.py --recursive -- bento run /app/bento/${PIPELINE}.yaml"]
