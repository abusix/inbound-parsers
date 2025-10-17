# inbound-parsers

Next-generation abuse report parser with Bento stream processing.

## Quick Start

```bash
# Install dependencies
make setup

# Start development environment
make dev-up

# Run tests
make test

# View logs
make dev-logs

# Open Grafana dashboard
make metrics
```

## Architecture

- **Bento** - Stream processing (Kafka consumer/producer, routing, offset management)
- **Python Workers** - FastAPI subprocess workers for specialized parsers
- **Monitoring** - Prometheus + Grafana + Loki (pre-configured dashboards)

## Current Parsers

- **FBL** (Feedback Loop) - RFC 9477 compliant CFBL parser

## Development

See `Makefile` for available commands.

Access points:
- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090
- Kafka UI: http://localhost:8080
