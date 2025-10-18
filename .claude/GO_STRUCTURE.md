# Go Parser Directory Structure Plan

*Created: 2025-10-18*
*Status: Planning - Not yet implemented*

## Overview

This document defines the directory structure for the Go-based parser implementation. This structure follows Go best practices and enables clean separation between parser libraries and Bento integration.

## Target Directory Structure

```
inbound-parsers/
├── go.mod                          # Go module definition
├── go.sum                          # Dependency checksums
├── .golangci.yml                   # Linter configuration
│
├── cmd/                            # Main applications
│   └── bento-parsers/              # Custom Bento binary
│       └── main.go                 # Bento entrypoint with custom processors
│
├── parsers/                        # Pure Go parser libraries (no Bento deps)
│   ├── fbl/                        # FBL parser package
│   │   ├── parser.go               # Main parser logic
│   │   ├── parser_test.go          # Unit tests
│   │   ├── models.go               # Event structs
│   │   ├── dkim.go                 # DKIM verification
│   │   ├── dkim_test.go            # DKIM tests
│   │   ├── ip.go                   # IP extraction
│   │   ├── ip_test.go              # IP tests
│   │   ├── received.go             # Received header parsing
│   │   ├── received_test.go        # Received header tests
│   │   └── testdata/               # Test fixtures
│   │       ├── valid_fbl.eml       # Valid FBL email
│   │       ├── invalid_dkim.eml    # DKIM failure test
│   │       └── multipart.eml       # Multipart email test
│   │
│   ├── shadowserver/               # ShadowServer parser (Phase 2)
│   │   ├── parser.go
│   │   ├── parser_test.go
│   │   └── testdata/
│   │
│   └── common/                     # Shared parser utilities
│       ├── email.go                # Email parsing helpers
│       ├── email_test.go
│       ├── validation.go           # Common validations
│       └── validation_test.go
│
├── bento/                          # Bento-specific code
│   ├── processors/                 # Custom Bento processors
│   │   ├── fbl_processor.go        # FBL processor (calls parsers/fbl)
│   │   ├── fbl_processor_test.go   # Integration tests
│   │   └── shadowserver_processor.go # ShadowServer (Phase 2)
│   │
│   ├── configs/                    # Bento YAML configs
│   │   ├── fbl.yaml                # FBL pipeline (updated for Go)
│   │   └── shadowserver.yaml       # ShadowServer pipeline (Phase 2)
│   │
│   └── build/                      # Build artifacts
│       └── .gitignore              # Ignore compiled binaries
│
├── scripts/                        # Development scripts
│   ├── compare-output.go           # V1 vs V2 output comparison
│   ├── send-test-message.go        # Kafka test message sender
│   └── run-comparison.sh           # Shell wrapper for comparison
│
├── tests/                          # Test organization
│   ├── fixtures/                   # Shared test data
│   │   ├── fbl/                    # FBL .eml files
│   │   │   ├── valid_dkim_strict.eml
│   │   │   ├── valid_dkim_relaxed.eml
│   │   │   ├── valid_dkim_third_party.eml
│   │   │   ├── invalid_no_cfbl.eml
│   │   │   └── multipart_complex.eml
│   │   └── shadowserver/           # ShadowServer samples (Phase 2)
│   │
│   ├── integration/                # Integration tests
│   │   ├── pipeline_test.go        # Full Bento pipeline tests
│   │   └── kafka_test.go           # Kafka integration tests
│   │
│   └── comparison/                 # V1 vs V2 comparison tests
│       ├── fbl_comparison_test.go  # Compare Go vs Python output
│       └── expected_outputs/       # Expected JSON outputs
│           └── fbl_valid_dkim_strict.json
│
├── docs/                           # Documentation
│   ├── architecture.md             # Architecture overview
│   ├── parsers/                    # Parser-specific docs
│   │   ├── fbl.md                  # FBL parser documentation
│   │   └── shadowserver.md         # ShadowServer docs (Phase 2)
│   └── development.md              # Development guide
│
├── monitoring/                     # Observability (unchanged)
│   ├── grafana/
│   ├── prometheus/
│   └── loki/
│
├── docker/                         # Docker files (Phase 2)
│   ├── Dockerfile.bento            # Bento container
│   └── docker-compose.yml          # Full stack
│
└── .github/                        # CI/CD
    └── workflows/
        └── ci.yml                  # Updated for Go tooling
```

## Directory Explanations

### `/cmd/bento-parsers/`
**Purpose:** Main application entry point
**Contains:** Custom Bento binary that registers our processors
**Why:** Go convention - executables in `cmd/`
**Example:**
```go
// cmd/bento-parsers/main.go
package main

import (
    "github.com/warpstreamlabs/bento/public/service"
    "github.com/abusix/inbound-parsers/bento/processors"
)

func main() {
    service.RunCLI(
        service.CLIOptOnLoggerInit(func(l *service.Logger) {
            processors.RegisterFBLProcessor()
            processors.RegisterShadowServerProcessor()
        }),
    )
}
```

### `/parsers/fbl/`
**Purpose:** Pure FBL parser library
**No dependencies on:** Bento, Kafka, HTTP frameworks
**Can be used by:** Bento processors, CLI tools, other Go programs
**Testing:** Standard Go unit tests with `testdata/`
**Coverage target:** 80%+

**Key files:**
- `parser.go` - Main `Parse(emailBytes []byte) (*Event, error)` function
- `models.go` - Event structs matching v1 output format
- `dkim.go` - DKIM verification (strict, relaxed, third-party)
- `ip.go` - IP extraction from headers
- `received.go` - Received header parsing for event_date

### `/parsers/common/`
**Purpose:** Shared utilities across all parsers
**Examples:**
- Email header parsing helpers
- IP validation functions
- Domain extraction utilities
- Common error types

### `/bento/processors/`
**Purpose:** Thin wrappers that call parser libraries
**Responsibilities:**
- Implement Bento processor interface
- Convert Bento messages to parser input
- Convert parser output to Bento messages
- Handle errors and metrics

**Example structure:**
```go
// bento/processors/fbl_processor.go
package processors

import (
    "github.com/warpstreamlabs/bento/public/service"
    "github.com/abusix/inbound-parsers/parsers/fbl"
)

func RegisterFBLProcessor() {
    service.RegisterProcessor(
        "fbl_parser",
        fblProcessorConfig(),
        fblProcessorConstructor,
    )
}

func fblProcessorConstructor(conf *service.ParsedConfig, mgr *service.Resources) (service.Processor, error) {
    return &FBLProcessor{logger: mgr.Logger()}, nil
}

type FBLProcessor struct {
    logger *service.Logger
}

func (p *FBLProcessor) Process(msg *service.Message) (service.MessageBatch, error) {
    // Get email bytes
    emailBytes, err := msg.AsBytes()
    if err != nil {
        return nil, err
    }

    // Call parser library
    event, err := fbl.Parse(emailBytes)
    if err != nil {
        return nil, err
    }

    // Convert to Bento message
    outMsg := msg.Copy()
    outMsg.SetStructured(event)

    return service.MessageBatch{outMsg}, nil
}
```

### `/tests/fixtures/`
**Purpose:** Shared test data for all tests
**Organization:**
- One directory per parser type
- Real-world .eml files copied from v1
- Cover all edge cases (DKIM modes, multipart, errors)

### `/tests/integration/`
**Purpose:** End-to-end pipeline tests
**Tests:**
- Full Bento pipeline (input → process → output)
- Kafka integration (produce → consume → verify)
- Error handling and retries

### `/tests/comparison/`
**Purpose:** Validate Go output matches Python v1 output
**Process:**
1. Run same .eml through v1 Python parser
2. Run same .eml through v2 Go parser
3. Compare JSON output (ignore timestamps/IDs)
4. Fail test if any differences found

## Go Module Setup

### `go.mod` Initial Dependencies

```go
module github.com/abusix/inbound-parsers

go 1.23

require (
    github.com/warpstreamlabs/bento v1.5.0
    github.com/emersion/go-msgauth v0.6.8  // DKIM verification
    github.com/stretchr/testify v1.9.0     // Test assertions
    github.com/prometheus/client_golang v1.20.0 // Metrics
)
```

## Linting Configuration

### `.golangci.yml`

```yaml
linters:
  enable:
    - errcheck      # Check for unchecked errors
    - gosimple      # Suggest code simplifications
    - govet         # Vet examines Go source code
    - ineffassign   # Detect ineffectual assignments
    - staticcheck   # Static analysis
    - unused        # Find unused code
    - gofmt         # Check formatting
    - goimports     # Check import ordering
    - misspell      # Find misspelled words
    - revive        # Flexible linting rules
    - gosec         # Security checks

linters-settings:
  errcheck:
    check-blank: true
  govet:
    enable-all: true
  revive:
    rules:
      - name: exported
        severity: warning
        disabled: false

run:
  timeout: 5m
  tests: true
```

## Testing Strategy

### Unit Tests
- **Location:** `parsers/fbl/*_test.go`
- **Scope:** Individual functions (DKIM, IP extraction, etc.)
- **Coverage:** 80%+ required
- **Command:** `go test ./parsers/...`

### Integration Tests
- **Location:** `tests/integration/*_test.go`
- **Scope:** Full pipeline with Bento
- **Requires:** Kafka test container
- **Command:** `go test ./tests/integration/...`

### Comparison Tests
- **Location:** `tests/comparison/*_test.go`
- **Scope:** V1 vs V2 output validation
- **Requires:** v1 parser accessible
- **Command:** `go test ./tests/comparison/...`

## Build Commands

### Local Development
```bash
# Build custom Bento binary
go build -o bento-parsers ./cmd/bento-parsers

# Run unit tests
go test ./parsers/...

# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Lint code
golangci-lint run
```

### Docker Build
```bash
# Build container
docker build -f docker/Dockerfile.bento -t inbound-parsers:latest .

# Run with docker-compose
docker-compose up -d
```

## Migration Checklist

### Phase 1: Setup (Week 1)
- [ ] Initialize `go.mod` with module name
- [ ] Create directory structure as defined above
- [ ] Add `.golangci.yml` linter config
- [ ] Update `.gitignore` for Go artifacts
- [ ] Copy test fixtures from v1 to `tests/fixtures/fbl/`
- [ ] Update CI/CD workflow for Go tooling

### Phase 2: FBL Parser (Week 1-2)
- [ ] Implement `parsers/fbl/models.go` (Event struct)
- [ ] Implement `parsers/fbl/parser.go` (main Parse function)
- [ ] Implement `parsers/fbl/dkim.go` (DKIM verification)
- [ ] Implement `parsers/fbl/ip.go` (IP extraction)
- [ ] Implement `parsers/fbl/received.go` (Received header parsing)
- [ ] Write unit tests for all packages
- [ ] Achieve 80%+ test coverage

### Phase 3: Bento Integration (Week 2)
- [ ] Implement `bento/processors/fbl_processor.go`
- [ ] Update `bento/configs/fbl.yaml` to use custom processor
- [ ] Implement `cmd/bento-parsers/main.go`
- [ ] Build and test custom Bento binary
- [ ] Write integration tests

### Phase 4: Validation (Week 2-3)
- [ ] Implement `scripts/compare-output.go`
- [ ] Run comparison tests against v1
- [ ] Fix any output differences
- [ ] Document intentional differences (if any)
- [ ] Benchmark performance (Go vs Python)

### Phase 5: Cleanup (Week 3)
- [ ] Delete `parsers/fbl.py`
- [ ] Delete `workers/fbl_worker.py`
- [ ] Delete `pyproject.toml`
- [ ] Update Dockerfile (remove Python)
- [ ] Update README.md
- [ ] Update monitoring dashboards
- [ ] Celebrate! 🎉

## Notes

### Why This Structure?

1. **Separation of Concerns**
   - Parsers are pure libraries (no framework dependencies)
   - Bento processors are thin wrappers
   - Easy to test each layer independently

2. **Go Conventions**
   - `cmd/` for executables
   - `internal/` for private code (if needed later)
   - `testdata/` for test fixtures
   - `*_test.go` for tests alongside code

3. **Scalability**
   - Easy to add new parsers (copy fbl/ structure)
   - Each parser is self-contained
   - Common utilities in `parsers/common/`

4. **Testability**
   - Unit tests don't need Kafka or Bento
   - Integration tests verify full pipeline
   - Comparison tests validate against v1

5. **Maintainability**
   - Clear boundaries between layers
   - Standard Go tooling (go test, golangci-lint)
   - Easy to onboard new developers

### Migration Path

This structure supports incremental migration:
- Week 1: Setup + FBL parser library
- Week 2: Bento integration + testing
- Week 3: Validation + cleanup
- Phase 2: Add more parsers (ShadowServer, etc.)

No need to migrate everything at once!

---

**Last Updated:** 2025-10-18
**Status:** ✅ Planning complete, ready for implementation
**Next Step:** Run `go mod init github.com/abusix/inbound-parsers`
