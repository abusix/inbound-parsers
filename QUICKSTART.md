# Inbound Parsers V2 - Quick Start Guide

## 🚀 What's Done

✅ **Foundation 100% Complete**
- All 393 parser stubs generated
- FBL parser fully implemented
- Binary compiles and runs
- Comparison tool ready

## 📦 Build & Run

```bash
# Build the binary
go build -o bento-parsers ./cmd/bento-parsers

# Process an email (JSON format from stdin)
./bento-parsers process < test_email.json

# Lint a Bento config
./bento-parsers lint bento/configs/fbl-processor-v2.yaml
```

## 🧪 Testing

```bash
# Run all tests
go test -v ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Compare V1 vs V2 output
go run scripts/compare-output.go v1_output.json v2_output.json
```

## 📊 Project Status

| Component | Status | Count |
|-----------|--------|-------|
| **Foundation** | ✅ Complete | 100% |
| **Fully Implemented Parsers** | ✅ FBL | 1/393 |
| **Parser Stubs** | ✅ Complete | 392/393 |
| **Tests** | 🚧 TODO | 0/? |

## 🎯 Next Steps

### Priority 1: ShadowServer Parser
```bash
# Location: parsers/shadowserver/shadowserver.go
# Lines to port: 1134
# Source: /tmp/abusix-parsers-old/abusix_parsers/parsers/parser/shadowserver.py
```

### Priority 2: CERT Parsers (18 total)
```bash
# All located in parsers/cert_*/
# Medium complexity (100-200 lines each)
```

### Priority 3: Testing Infrastructure
```bash
# Copy test fixtures
cp -r /tmp/abusix-parsers-old/tests/data/sample_mails tests/fixtures/

# Implement unit tests
# See: tests/unit/fbl_test.go (TODO)
```

## 📁 Key Files

```
cmd/bento-parsers/main.go              # Main binary
parsers/base/parser.go                 # BaseParser interface
parsers/common/string.go               # String utilities
parsers/fbl/fbl.go                    # FBL parser (COMPLETE)
events/event.go                        # Event models
.claude/MIGRATION_STATUS.md            # Detailed status
```

## 🔄 V1 vs V2 Parallel Deployment

```yaml
# V1 (Python) outputs to:
topic: fbl-events

# V2 (Go) outputs to:
topic: fbl-events-v2

# Comparison:
compare-output v1_output.json v2_output.json
```

## 📚 Documentation

- **MIGRATION_STATUS.md** - Complete migration status
- **GO_TOOLING.md** - Tooling and quality gates
- **QUALITY_GATES.md** - Pre-commit vs CI alignment
- **CONTEXT.md** - Project context and architecture

## 🆘 Need Help?

```bash
# Check migration status
cat .claude/MIGRATION_STATUS.md

# View parser stub
cat parsers/shadowserver/shadowserver.go

# Compare with Python version
cat /tmp/abusix-parsers-old/abusix_parsers/parsers/parser/shadowserver.py
```

## ⚡ Performance Tips

- Use swarms for parallel parser implementation
- Batch similar parsers (CERT, brand protection, etc.)
- Run comparison tests continuously
- Monitor metrics during parallel deployment

---

**Status:** 🟢 Ready for accelerated development
**Last Updated:** 2025-10-18
