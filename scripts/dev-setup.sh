#!/bin/bash
set -e

echo "🚀 Setting up inbound-parsers development environment..."

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "❌ docker-compose is required but not installed. Aborting." >&2; exit 1; }
command -v poetry >/dev/null 2>&1 || { echo "❌ Poetry is required but not installed. Aborting." >&2; exit 1; }

# Install Python dependencies
echo "📦 Installing Python dependencies..."
poetry install

# Install pre-commit hooks
echo "🔧 Installing pre-commit hooks..."
poetry run pre-commit install

# Initialize detect-secrets baseline
if [ ! -f .secrets.baseline ]; then
    echo "🔒 Creating secrets baseline..."
    poetry run detect-secrets scan > .secrets.baseline
fi

# Create Kafka topics
echo "🎯 Starting Kafka to create topics..."
docker-compose -f docker-compose.dev.yml up -d kafka zookeeper
sleep 10  # Wait for Kafka to be ready

docker-compose -f docker-compose.dev.yml exec -T kafka kafka-topics \
    --create --if-not-exists \
    --bootstrap-server localhost:9092 \
    --topic smtp_input \
    --partitions 3 \
    --replication-factor 1 || true

docker-compose -f docker-compose.dev.yml exec -T kafka kafka-topics \
    --create --if-not-exists \
    --bootstrap-server localhost:9092 \
    --topic fbl-events \
    --partitions 3 \
    --replication-factor 1 || true

echo "✅ Development environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Run 'make dev-up' to start all services"
echo "  2. Run 'make kafka-produce-test' to send test messages"
echo "  3. Open http://localhost:3000 for Grafana (admin/admin)"
echo "  4. Run 'make test' to run tests"
