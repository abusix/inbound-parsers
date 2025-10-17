#!/bin/bash
set -e

echo "🧹 Resetting inbound-parsers development environment..."

# Stop all services
echo "⏹️  Stopping all services..."
docker-compose -f docker-compose.dev.yml down -v

# Clean up volumes
echo "🗑️  Removing volumes..."
docker volume rm inbound-parsers-dev_prometheus-data 2>/dev/null || true
docker volume rm inbound-parsers-dev_grafana-data 2>/dev/null || true
docker volume rm inbound-parsers-dev_loki-data 2>/dev/null || true

# Clean Python artifacts
echo "🐍 Cleaning Python artifacts..."
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name '*.pyc' -delete 2>/dev/null || true
rm -rf .pytest_cache .mypy_cache htmlcov .coverage 2>/dev/null || true

# Rebuild containers
echo "🔨 Rebuilding containers..."
docker-compose -f docker-compose.dev.yml build --no-cache

echo "✅ Environment reset complete!"
echo ""
echo "Run 'make dev-up' to start fresh"
