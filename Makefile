.PHONY: help setup test lint format type-check security clean run-fbl logs metrics compare dev-up dev-down dev-reset

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Initial project setup
	@echo "🔧 Setting up inbound-parsers development environment..."
	poetry install
	poetry run pre-commit install
	@echo "✅ Setup complete! Run 'make dev-up' to start services"

test: ## Run all tests with coverage
	poetry run pytest -v

test-unit: ## Run unit tests only
	poetry run pytest tests/unit -v

test-integration: ## Run integration tests
	poetry run pytest tests/integration -v

test-comparison: ## Run v1 vs v2 comparison tests
	poetry run pytest tests/comparison -v

lint: ## Run all linters
	poetry run flake8 parsers workers tests
	poetry run mypy parsers workers

format: ## Format code with black and isort
	poetry run black parsers workers tests
	poetry run isort parsers workers tests

type-check: ## Run mypy type checking
	poetry run mypy parsers workers

security: ## Run security checks
	poetry run bandit -r parsers workers
	poetry run detect-secrets scan

clean: ## Clean up generated files
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	find . -type d -name '*.egg-info' -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache htmlcov .coverage

dev-up: ## Start development environment
	docker-compose -f docker-compose.dev.yml up -d
	@echo "🚀 Development environment started!"
	@echo "📊 Grafana: http://localhost:3000 (admin/admin)"
	@echo "📈 Prometheus: http://localhost:9090"
	@echo "🔍 Kafka UI: http://localhost:8080"

dev-down: ## Stop development environment
	docker-compose -f docker-compose.dev.yml down

dev-reset: ## Reset development environment (clean slate)
	./scripts/dev-reset.sh

dev-logs: ## Follow logs from all services
	docker-compose -f docker-compose.dev.yml logs -f

run-fbl: ## Run FBL parser locally
	poetry run uvicorn workers.fbl_worker:app --reload --port 8001

logs: ## View Bento logs
	docker-compose -f docker-compose.dev.yml logs -f bento-fbl

metrics: ## Open Grafana metrics dashboard
	@open http://localhost:3000/d/inbound-parsers/overview || echo "Grafana at http://localhost:3000"

compare: ## Run comparison between v1 and v2 output
	poetry run python scripts/compare-output.py

kafka-consume-fbl: ## Consume FBL output topic
	docker-compose -f docker-compose.dev.yml exec kafka kafka-console-consumer \
		--bootstrap-server localhost:9092 \
		--topic fbl-events \
		--from-beginning \
		--property print.key=true

kafka-produce-test: ## Send test message to input topic
	poetry run python scripts/send-test-message.py

ci: lint test ## Run CI checks locally
	@echo "✅ All CI checks passed!"
