# Makefile for inbound-parsers (Go implementation)
# ============================================================================

.PHONY: help go-setup go-verify go-fmt go-lint go-sec go-test go-check go-build go-clean
.PHONY: yaml-lint bento-lint trivy-fs trivy-image security-scan
.PHONY: dev-up dev-down dev-reset dev-logs run-bento
.PHONY: kafka-consume-fbl kafka-produce-test compare ci

# Go configuration
GO_VERSION := 1.23
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')
BINARY_NAME := bento-parsers

# ============================================================================
# Help
# ============================================================================

help: ## Show this help message
	@echo 'inbound-parsers - Go-based parser implementation'
	@echo ''
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ============================================================================
# Go Setup & Verification
# ============================================================================

go-setup: ## Install all Go tooling (one-time setup)
	@echo "🔧 Installing Go development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	@echo "🔧 Installing pre-commit hooks..."
	pip install pre-commit
	pre-commit install
	@echo "🔧 Installing YAML linting tools..."
	pip install yamllint
	@echo "✅ Go tooling installed! Run 'make go-verify' to check."

go-verify: ## Verify all tools are installed correctly
	@echo "🔍 Verifying Go installation..."
	@go version || (echo "❌ Go not installed"; exit 1)
	@echo "🔍 Verifying Go tools..."
	@golangci-lint version || (echo "❌ golangci-lint not installed"; exit 1)
	@goimports -h > /dev/null || (echo "❌ goimports not installed"; exit 1)
	@gosec -version || (echo "❌ gosec not installed"; exit 1)
	@govulncheck -h > /dev/null || (echo "❌ govulncheck not installed"; exit 1)
	@yamllint --version || (echo "❌ yamllint not installed"; exit 1)
	@echo "✅ All tools verified!"

# ============================================================================
# Go Code Quality (replaces Python lint/format)
# ============================================================================

go-fmt: ## Format Go code (replaces black)
	@echo "🎨 Formatting Go code..."
	gofmt -s -w $(GO_FILES)
	goimports -w $(GO_FILES)
	@echo "✅ Code formatted!"

go-lint: ## Run golangci-lint (replaces flake8)
	@echo "🔍 Running golangci-lint..."
	golangci-lint run --config=.golangci.yml --timeout=5m
	@echo "✅ Linting passed!"

go-vet: ## Run go vet static analysis
	@echo "🔍 Running go vet..."
	go vet ./...
	@echo "✅ go vet passed!"

go-sec: ## Run security scanner (replaces bandit)
	@echo "🔒 Running gosec security scan..."
	gosec -conf .golangci.yml ./...
	@echo "✅ Security scan passed!"

go-vuln: ## Check for known vulnerabilities
	@echo "🔒 Checking for known vulnerabilities..."
	govulncheck ./...
	@echo "✅ No known vulnerabilities!"

# ============================================================================
# YAML Quality (Bento configs)
# ============================================================================

yaml-lint: ## Validate YAML files
	@echo "📄 Validating YAML files..."
	yamllint -c .yamllint.yml .
	@echo "✅ YAML validation passed!"

bento-lint: ## Validate Bento configuration files
	@echo "📋 Validating Bento configs..."
	./$(BINARY_NAME) lint bento/configs/*.yaml
	@echo "✅ Bento configs valid!"

# ============================================================================
# Testing (replaces pytest)
# ============================================================================

go-test: ## Run all Go tests with coverage
	@echo "🧪 Running Go tests..."
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "📊 Coverage report:"
	go tool cover -func=coverage.out | tail -n 1

go-test-unit: ## Run unit tests only
	@echo "🧪 Running unit tests..."
	go test -v -short -race ./parsers/...

go-test-integration: ## Run integration tests
	@echo "🧪 Running integration tests..."
	go test -v -tags=integration ./tests/integration/...

go-test-coverage: ## Generate HTML coverage report
	@echo "📊 Generating coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report: coverage.html"

# ============================================================================
# Security Scanning (multi-layer)
# ============================================================================

trivy-fs: ## Scan filesystem for vulnerabilities
	@echo "🔒 Running Trivy filesystem scan..."
	trivy fs --config .trivy.yaml .
	@echo "✅ Filesystem scan passed!"

trivy-image: ## Scan Docker image for vulnerabilities
	@echo "🔒 Running Trivy container scan..."
	trivy image --config .trivy.yaml $(BINARY_NAME):latest
	@echo "✅ Container scan passed!"

trivy-config: ## Scan for IaC misconfigurations
	@echo "🔒 Scanning for misconfigurations..."
	trivy config --config .trivy.yaml .
	@echo "✅ Configuration scan passed!"

detect-secrets: ## Scan for secrets in codebase
	@echo "🔒 Scanning for secrets..."
	detect-secrets scan --baseline .secrets.baseline
	@echo "✅ No secrets detected!"

security-scan: go-sec go-vuln trivy-fs detect-secrets ## Run all security scans
	@echo "🔒 All security scans passed!"

# ============================================================================
# Build & Clean
# ============================================================================

go-build: ## Build the Bento binary
	@echo "🔨 Building $(BINARY_NAME)..."
	go build -v -o $(BINARY_NAME) ./cmd/bento-parsers
	@echo "✅ Build complete: ./$(BINARY_NAME)"

go-build-all: ## Build for all platforms
	@echo "🔨 Building for all platforms..."
	GOOS=linux GOARCH=amd64 go build -v -o $(BINARY_NAME)-linux-amd64 ./cmd/bento-parsers
	GOOS=linux GOARCH=arm64 go build -v -o $(BINARY_NAME)-linux-arm64 ./cmd/bento-parsers
	GOOS=darwin GOARCH=amd64 go build -v -o $(BINARY_NAME)-darwin-amd64 ./cmd/bento-parsers
	GOOS=darwin GOARCH=arm64 go build -v -o $(BINARY_NAME)-darwin-arm64 ./cmd/bento-parsers
	@echo "✅ All builds complete!"

go-clean: ## Clean Go build artifacts
	@echo "🧹 Cleaning Go build artifacts..."
	go clean
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*
	rm -f coverage.out coverage.html
	rm -rf bento/build/*
	@echo "✅ Cleaned!"

# ============================================================================
# Combined Quality Checks
# ============================================================================

go-check: go-fmt go-vet go-lint go-test ## Run all Go quality checks (pre-commit)
	@echo "✅ All Go checks passed!"

ci: go-check security-scan yaml-lint ## Run full CI checks locally
	@echo "✅ All CI checks passed! Ready to push."

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
