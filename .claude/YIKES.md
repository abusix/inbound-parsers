# YIKES - Known Issues (inbound-parsers v2)

*Last verified: 2025-10-18*

## 🟡 MEDIUM PRIORITY

1. **[Dependencies] Missing required Python libraries**
   - Location: `pyproject.toml`
   - Issue: FBL parser needs libraries not yet added to dependencies
   - Missing:
     - `dkimpy` - DKIM signature verification
     - `tldextract` - Domain parsing and extraction
     - `ahq_events` - Event models (need to verify if public/internal)
     - `ahq_parser_processors` - IP extraction helpers (need to verify if public/internal)
   - Impact: Code won't run until dependencies added
   - Fix needed: Add to `[tool.poetry.dependencies]` or copy code if internal

2. **[Testing] No test data or fixtures**
   - Location: `tests/fixtures/` (doesn't exist yet)
   - Issue: Need sample FBL .eml files for testing
   - Source: Copy from v1 `sample_mails/` directory
   - Fix needed: Create test data loader script

3. **[Testing] No test suite implemented**
   - Location: `tests/` (empty)
   - Issue: No unit, integration, or comparison tests written
   - Impact: Can't validate parser correctness
   - Fix needed:
     - Unit tests for FBL parser (DKIM, IP extraction, error handling)
     - Integration tests (full pipeline)
     - Comparison tests (v1 vs v2 output)

4. **[Monitoring] No Grafana dashboard JSON**
   - Location: `monitoring/grafana/dashboards/` (empty)
   - Issue: Dashboard provisioning configured but no dashboard exists
   - Impact: Have to create dashboard manually
   - Fix needed: Create `fbl-overview.json` with panels for metrics

5. **[Code] Simplified ReceivedHeader parsing**
   - Location: `parsers/fbl.py:219` (commented out)
   - Issue: Event date extraction not implemented
   - Impact: Events have `event_date: null`
   - Fix needed: Copy `ReceivedHeader` class from v1 or implement proper date parsing

6. **[Code] Simplified IP extraction**
   - Location: `parsers/fbl.py:233-239`
   - Issue: Using regex instead of proper IP extraction library
   - Impact: May miss valid IPs or extract invalid ones
   - Fix needed: Use `ahq_parser_processors.extract_all_ipv4` or copy implementation

## 🟢 LOW PRIORITY / TECH DEBT

7. **[Config] No poetry.lock file**
   - Location: Root directory
   - Issue: `poetry.lock` is gitignored (intentional for libraries)
   - Impact: Dependency versions not pinned
   - Fix needed: Run `poetry install` to generate, then decide if we should commit it

8. **[Scripts] Missing test data loader**
   - Location: `scripts/send-test-message.py` (doesn't exist)
   - Issue: No way to send test messages to Kafka
   - Impact: Can't test locally without manual Kafka commands
   - Fix needed: Create script to send .eml files to Kafka

9. **[Scripts] Missing comparison test tool**
   - Location: `scripts/compare-output.py` (referenced in Makefile but doesn't exist)
   - Issue: No way to compare v1 vs v2 output
   - Impact: Can't validate migration correctness
   - Fix needed: Create comparison tool

10. **[Docs] Missing .env.example**
    - Location: Root directory
    - Issue: No template for environment variables
    - Impact: Developers don't know what env vars are needed
    - Fix needed: Create `.env.example` with all variables documented

11. **[Code] No email multipart handling**
    - Location: `workers/fbl_worker.py:90`
    - Issue: `parts=[]` always empty, multipart emails not parsed
    - Impact: May miss CFBL-Address in embedded message/rfc822 parts
    - Fix needed: Implement multipart parsing (copy from v1 `mail_parser.py`)

12. **[Security] No secrets baseline initialized**
    - Location: `.secrets.baseline` (doesn't exist)
    - Issue: Pre-commit hook will fail on first run
    - Impact: Can't commit until baseline created
    - Fix needed: Run `detect-secrets scan > .secrets.baseline`

## 📋 KNOWN LIMITATIONS (By Design)

13. **[Architecture] FBL only**
    - Status: Intentional - starting with one parser
    - Impact: Can't process other abuse report types yet
    - Plan: Add more parsers incrementally

14. **[Performance] Subprocess overhead**
    - Status: Accepted trade-off for simplicity
    - Measured: ~0.5ms overhead vs direct call
    - Plan: Upgrade to Unix socket HTTP if needed (after benchmarking)

15. **[Testing] No load testing**
    - Status: Not implemented yet
    - Impact: Don't know max throughput
    - Plan: Add in Phase 3 (production readiness)

## ✅ FIXED (Compared to v1)

16. **[FIXED] Kafka auto-commit data loss**
    - v1 Issue: Auto-commit every 5s without manual commit after output
    - v2 Fix: Bento `commit_period: "0s"` + manual commit after output
    - Status: ✅ Fixed by design

17. **[FIXED] FBL rejection by abuse report logic**
    - v1 Issue: FBL emails run through `001_mail_reject.py`
    - v2 Fix: Separate FBL pipeline, no rejection logic
    - Status: ✅ Fixed by design

18. **[FIXED] No observability**
    - v1 Issue: No metrics, structured logging, or dashboards
    - v2 Fix: Prometheus + Grafana + Loki from day 1
    - Status: ✅ Fixed by design

---

**Next Steps:**
1. Add missing dependencies to `pyproject.toml`
2. Run `poetry install` to test dependency resolution
3. Create test fixtures directory
4. Initialize secrets baseline
5. Write first unit test
