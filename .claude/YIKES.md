# YIKES - Known Issues (inbound-parsers v2)

*Last verified: 2025-10-18 (qinit)*

## 🚨 ARCHITECTURE CHANGE NOTICE (2025-10-18)

**Decision:** Migration from Python to Pure Go architecture
- Parsers will be rewritten in Go (not Python)
- Python code (`parsers/fbl.py`, `workers/fbl_worker.py`, `pyproject.toml`) will be **deleted**
- Many Python-specific issues below are now **OBSOLETE** (marked with 🗑️)
- See `.claude/CONTEXT.md` for full migration roadmap

## 🔴 CRITICAL - BLOCKERS

1. 🗑️ **[OBSOLETE - Python Dependencies] Missing required Python libraries** *(Confirmed 2025-10-18)*
   - Status: **MOOT** - Python code will be deleted in Go migration
   - Location: `pyproject.toml`
   - Code locations: `parsers/fbl.py:12-13`
   - Issue: FBL parser imports libraries not in pyproject.toml
   - Missing:
     - `dkimpy` - DKIM signature verification (imported line 12)
     - `tldextract` - Domain parsing (imported line 13)
     - `ahq_events` - Event models (referenced but not imported)
     - `ahq_parser_processors` - IP extraction helpers (referenced but not imported)
   - Go equivalent: Use `github.com/emersion/go-msgauth` for DKIM
   - **No action needed** - will be resolved by Go rewrite

2. **[Scripts] Missing scripts referenced in Makefile** *(Discovered 2025-10-18)*
   - Location: `scripts/` directory
   - Issue: Makefile commands reference non-existent scripts
   - Missing:
     - `scripts/compare-output.py` - `make compare` will fail (Makefile:74)
     - `scripts/send-test-message.py` - `make kafka-produce-test` will fail (Makefile:84)
   - Impact: **Essential development commands broken**
   - Fix needed: Create these scripts (can be in Go or Python)
   - Note: Comparison script still needed for v1 vs v2 validation

## 🟡 MEDIUM PRIORITY

3. **[Testing] No test data or fixtures** *(Confirmed 2025-10-18)* ✅ Still applies
   - Location: `tests/fixtures/` (doesn't exist yet)
   - Status: All test directories empty (unit/, integration/, comparison/)
   - Issue: Need sample FBL .eml files for testing
   - Source: Copy from v1 `sample_mails/` directory
   - Impact: Cannot write or run tests without fixtures
   - Fix needed: Create fixtures directory and populate with .eml files
   - **Still needed for Go tests**

4. **[Testing] No test suite implemented** *(Confirmed 2025-10-18)* ✅ Still applies
   - Location: `tests/unit/`, `tests/integration/`, `tests/comparison/`
   - Status: All directories empty (verified with ls -la)
   - Issue: No unit, integration, or comparison tests written
   - Impact: CI passes with 0 tests (misleading green checkmark)
   - Fix needed:
     - Go unit tests for FBL parser (`parsers/fbl/parser_test.go`)
     - Integration tests (full Bento pipeline)
     - Comparison tests (v1 vs v2 output)
   - **Rewrite tests in Go, not Python**

5. **[Monitoring] No Grafana dashboard JSON** *(Confirmed 2025-10-18)* ✅ Still applies
   - Location: `monitoring/grafana/dashboards/` (empty - verified)
   - Issue: Dashboard provisioning configured but no dashboard exists
   - Impact: Have to create dashboard manually in Grafana UI
   - Fix needed: Create `fbl-overview.json` with panels for metrics
   - Metrics available: Bento + custom Bento processor Prometheus endpoints
   - **Still needed regardless of language**

6. 🗑️ **[OBSOLETE - Python Code] Simplified ReceivedHeader parsing**
   - Status: **MOOT** - Python parser will be deleted
   - Location: `parsers/fbl.py:219` (commented out)
   - Issue: Event date extraction not implemented
   - Go equivalent: Implement `Received` header parsing in `parsers/fbl/received.go`
   - **Will be rewritten in Go**

7. 🗑️ **[OBSOLETE - Python Code] Simplified IP extraction**
   - Status: **MOOT** - Python parser will be deleted
   - Location: `parsers/fbl.py:233-239`
   - Issue: Using regex instead of proper IP extraction library
   - Go equivalent: Use proper IP parsing in `parsers/fbl/ip_extraction.go`
   - **Will be rewritten in Go**

## 🟢 LOW PRIORITY / TECH DEBT

8. 🗑️ **[OBSOLETE - Poetry] No poetry.lock file** *(Verified 2025-10-18)*
   - Status: **MOOT** - `pyproject.toml` will be deleted in Go migration
   - Location: Root directory
   - Go equivalent: Use `go.mod` and `go.sum` for dependency locking
   - **No action needed** - Python dependencies obsolete

9. **[Docs] Missing .env.example** *(Verified 2025-10-18)* ✅ Still applies
   - Location: Root directory (doesn't exist)
   - Issue: No template for environment variables
   - Impact: Developers don't know what env vars are needed for docker-compose
   - Fix needed: Create `.env.example` with KAFKA_*, LOG_LEVEL, etc.
   - Note: WORKER_URL will be removed (no HTTP worker in Go architecture)
   - **Still needed for docker-compose**

10. 🗑️ **[OBSOLETE - Python Code] No email multipart handling**
    - Status: **MOOT** - Python worker will be deleted
    - Location: `workers/fbl_worker.py:90`
    - Issue: `parts=[]` always empty, multipart emails not parsed
    - Go equivalent: Use `mime/multipart` package in `parsers/fbl/parser.go`
    - **Will be rewritten in Go**

11. **[Security] No secrets baseline initialized** *(Critical for CI)* ✅ Still applies
    - Location: `.secrets.baseline` (doesn't exist)
    - Blocker: CI job expects this file (.github/workflows/ci.yml:64)
    - Issue: Pre-commit hook will fail on first run
    - Impact: **CI will fail** on security job
    - Fix needed: Run `detect-secrets scan > .secrets.baseline`
    - Priority: High - blocks CI from passing
    - **Still needed regardless of language**

## 📋 KNOWN LIMITATIONS (By Design)

12. **[Architecture] FBL only** *(By design)* ✅ Still applies
    - Status: Intentional - starting with one parser
    - Impact: Can't process other abuse report types yet
    - Plan: Add more parsers incrementally per roadmap (Phase 2)
    - **First Go parser: FBL, then ShadowServer, then others**

13. 🗑️ **[OBSOLETE - Subprocess overhead] Performance concern resolved**
    - Status: **MOOT** - Go architecture eliminates subprocess overhead
    - Old issue: ~0.5ms overhead from Python subprocess + HTTP
    - Go solution: Direct function calls in Bento processor (nanosecond overhead)
    - **Resolved by architecture change**

14. **[Testing] No load testing** *(Future work)* ✅ Still applies
    - Status: Not implemented yet
    - Impact: Don't know max throughput or breaking points
    - Plan: Add in Phase 3 (production readiness)
    - **Still needed for Go implementation**

## ✅ FIXED (Compared to v1)

15. **[FIXED] Kafka auto-commit data loss**
    - v1 Issue: Auto-commit every 5s without manual commit after output
    - v2 Fix: Bento `commit_period: "0s"` + manual commit after output (bento/fbl.yaml:23)
    - Status: ✅ Fixed by design

16. **[FIXED] FBL rejection by abuse report logic**
    - v1 Issue: FBL emails run through `001_mail_reject.py`
    - v2 Fix: Separate FBL pipeline, tag-based filtering only (bento/fbl.yaml:42-52)
    - Status: ✅ Fixed by design

17. **[FIXED] No observability**
    - v1 Issue: No metrics, structured logging, or dashboards
    - v2 Fix: Prometheus + Grafana + Loki from day 1 (monitoring/ directory)
    - Status: ✅ Fixed by design

---

## 📊 Summary *(Updated 2025-10-18 - Post Go Migration Decision)*

### Issue Status After Architecture Change

- **CRITICAL Blockers:** 1 active (down from 2)
  - 🗑️ Python dependencies → OBSOLETE (will be deleted)
  - ✅ Missing scripts → STILL NEEDED (for comparison testing)

- **MEDIUM Priority:** 3 active (down from 5)
  - ✅ Test fixtures → STILL NEEDED (for Go tests)
  - ✅ Test suite → STILL NEEDED (rewrite in Go)
  - ✅ Grafana dashboard → STILL NEEDED
  - 🗑️ ReceivedHeader parsing → OBSOLETE (will be rewritten in Go)
  - 🗑️ IP extraction → OBSOLETE (will be rewritten in Go)

- **LOW Priority:** 2 active (down from 4)
  - 🗑️ poetry.lock → OBSOLETE (Python obsolete)
  - ✅ .env.example → STILL NEEDED
  - 🗑️ Multipart handling → OBSOLETE (will be rewritten in Go)
  - ✅ Secrets baseline → STILL NEEDED

- **By Design:** 2 active (down from 3)
  - ✅ FBL only → STILL APPLIES
  - 🗑️ Subprocess overhead → RESOLVED BY GO ARCHITECTURE
  - ✅ No load testing → STILL APPLIES

- **Fixed from v1:** 3 major issues resolved (unchanged)

### Immediate Actions Required (Go Migration Path)

**Phase 0 - Pre-Migration Setup:**
1. ✅ Initialize secrets baseline: `detect-secrets scan > .secrets.baseline`
2. ✅ Create test fixtures directory and copy .eml files from v1
3. ✅ Create comparison script (`scripts/compare-output.py` or `.go`)
4. ✅ Create `.env.example` template

**Phase 1 - Go FBL Parser (see CONTEXT.md for full roadmap):**
1. Initialize `go.mod` and Go project structure
2. Create `parsers/fbl/` package with parser logic
3. Write Go unit tests (`parsers/fbl/parser_test.go`)
4. Create custom Bento processor wrapper
5. Build custom Bento binary
6. Run comparison tests (v1 vs v2)
7. Delete Python code

**Python Issues Now Obsolete:** 5 issues will be resolved by deleting Python code
**Issues Still Relevant:** 6 issues still need attention in Go implementation
