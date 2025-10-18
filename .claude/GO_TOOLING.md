# Go Tooling Stack - Complete Setup Guide

*Created: 2025-10-18*
*Status: Ready for implementation*
*Project: inbound-parsers v2 (Go migration)*

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Python → Go Tool Mapping](#python--go-tool-mapping)
3. [Essential Tools](#essential-tools)
4. [Installation](#installation)
5. [Configuration Files](#configuration-files)
6. [Daily Workflow](#daily-workflow)
7. [CI/CD Pipeline](#cicd-pipeline)
8. [Security Stack](#security-stack)
9. [Dependency Management](#dependency-management)
10. [Troubleshooting](#troubleshooting)

---

## Overview

This document defines the complete Go tooling stack for inbound-parsers v2, replacing Python tools (black, flake8, mypy, bandit, etc.) with Go equivalents.

**Goals:**
- ✅ Match or exceed Python tooling quality
- ✅ Faster CI/CD pipeline (Go tools are 10-100x faster)
- ✅ Zero-configuration where possible
- ✅ Comprehensive security scanning
- ✅ Automated dependency updates

**Stack components:**
- **Code Quality:** golangci-lint, gofmt, goimports
- **YAML Quality:** yamllint, bento lint (built-in Bento validator)
- **Security:** gosec, govulncheck, trivy, gitleaks
- **Dependencies:** Renovate (automated updates)
- **Testing:** go test (built-in)
- **CI/CD:** GitHub Actions

---

## Python → Go Tool Mapping

| Python Tool | Go Equivalent | Purpose | Notes |
|------------|---------------|---------|-------|
| **black** | `gofmt` | Code formatting | Zero-config, deterministic |
| **isort** | `goimports` | Import sorting | Also formats code |
| **flake8** | `golangci-lint` | Linting | Runs 50+ linters |
| **mypy** | Go compiler | Type checking | Built into language |
| **bandit** | `gosec` | Security scanning | Included in golangci-lint |
| **detect-secrets** | `gitleaks` | Secret detection | Can keep detect-secrets too |
| **pytest** | `go test` | Testing | Built-in, no install needed |
| **coverage.py** | `go test -cover` | Code coverage | Built-in |
| **poetry** | `go mod` | Dependency management | Built-in |
| **dependabot** | `renovate` | Auto-updates | More powerful |
| **N/A** | `trivy` | Container/vuln scanner | Multi-purpose security |
| **N/A** | `govulncheck` | Go vuln database | Official tool |
| **yamllint (Python)** | `yamllint` | YAML validation | Keep for Bento configs |
| **N/A** | `bento lint` | Bento config validator | Built into Bento |

**Key differences:**
- Go tools are **built-in** (gofmt, go test, go mod, go vet)
- Go tools are **faster** (compiled, not interpreted)
- Less configuration needed (gofmt has zero config)
- Type checking is **compile-time** (no separate mypy step)

---

## Essential Tools

### Core Go Tools (Built-in)

These come with Go installation - no setup needed:

```bash
go version    # Check Go version
gofmt         # Format Go code
go vet        # Static analysis
go test       # Run tests
go mod        # Manage dependencies
go build      # Build binaries
```

### Additional Tools (Install Once)

```bash
# Meta-linter (replaces flake8 + many others)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Import formatter (replaces isort)
go install golang.org/x/tools/cmd/goimports@latest

# Security scanner (replaces bandit)
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Vulnerability scanner (official Go tool)
go install golang.org/x/vuln/cmd/govulncheck@latest

# Advanced static analysis
go install honnef.co/go/tools/cmd/staticcheck@latest
```

### Container & Multi-Purpose Security

```bash
# macOS
brew install aquasecurity/trivy/trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Verify installation
trivy --version
```

### Secret Detection

```bash
# Option 1: gitleaks (Go-native)
brew install gitleaks

# Option 2: Keep detect-secrets (Python)
pip install detect-secrets
```

### YAML Quality Tools

```bash
# yamllint - YAML syntax and style checker
# (Needed for Bento config files)

# macOS
brew install yamllint

# Linux (Debian/Ubuntu)
sudo apt-get install yamllint

# Linux (RedHat/CentOS)
sudo yum install yamllint

# Or via pip (cross-platform)
pip install yamllint

# Bento lint - Built-in Bento config validator
# (Already available if you have Bento installed)
./bento-parsers lint --help
```

**Why both tools?**
- `yamllint` - General YAML syntax and style validation
- `bento lint` - Bento-specific validation (processors, inputs, outputs, etc.)
- Use both for comprehensive Bento config quality checks

---

## Installation

### Quick Setup (Recommended)

Run this after initializing `go.mod`:

```bash
# 1. Install all Go tools
make go-setup

# 2. Install Trivy
brew install aquasecurity/trivy/trivy  # macOS
# OR follow Linux instructions above

# 3. Verify everything installed
make go-verify
```

### Manual Setup

```bash
# Install Go tools one by one
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install honnef.co/go/tools/cmd/staticcheck@latest

# Add to PATH (if not already)
export PATH="$PATH:$(go env GOPATH)/bin"

# Verify
golangci-lint version
goimports -h
gosec -version
govulncheck -h
trivy --version
```

---

## Configuration Files

### 1. `.golangci.yml` - Linting Configuration

**Location:** Repo root
**Purpose:** Configure golangci-lint (replaces flake8)
**See:** Full file below in "Configuration Files Reference"

Key settings:
- 50+ linters enabled
- Zero warnings policy (CI fails on warnings)
- Custom rules for error handling
- Security checks via gosec
- Performance checks

### 2. `.trivy.yaml` - Security Scanner Configuration

**Location:** Repo root
**Purpose:** Configure Trivy security scanning
**See:** Full file below in "Configuration Files Reference"

Key settings:
- Scan severity: HIGH, CRITICAL
- Skip test directories
- Dockerfile best practices
- Vulnerability database updates

### 3. `renovate.json` - Dependency Automation

**Location:** Repo root
**Purpose:** Auto-update dependencies
**See:** Full file below in "Configuration Files Reference"

Key settings:
- Weekly Go dependency updates
- Auto-merge minor/patch versions
- Manual review for major versions
- Security updates immediate
- Group updates to reduce noise

### 4. `.pre-commit-config.yaml` - Pre-commit Hooks

**Location:** Repo root
**Purpose:** Run checks before each commit
**See:** Full file below in "Configuration Files Reference"

Runs on commit:
- gofmt (formatting)
- goimports (imports)
- go vet (static analysis)
- golangci-lint (linting)
- gosec (security)
- detect-secrets (secrets)

### 5. `.yamllint.yml` - YAML Quality Configuration

**Location:** Repo root
**Purpose:** Validate Bento YAML config files
**See:** Full file below in "Configuration Files Reference"

Key settings:
- Syntax validation
- Line length limits
- Indentation rules (2 spaces)
- Trailing spaces check
- Empty lines check

### 6. `.github/workflows/ci.yml` - CI Pipeline

**Location:** `.github/workflows/`
**Purpose:** Run full test suite in CI
**See:** Full file below in "Configuration Files Reference"

CI jobs:
- Lint (golangci-lint, yamllint)
- Security (gosec, govulncheck, trivy)
- Test (go test with coverage)
- Build (go build)
- Docker Security (trivy image scan)
- Bento Config Validation (bento lint)

---

## Daily Workflow

### Before Starting Work

```bash
# 1. Pull latest changes
git checkout main
git pull

# 2. Create feature branch
git checkout -b feature/my-feature

# 3. Verify tooling is installed
make go-verify
```

### During Development

```bash
# Format code automatically
make go-fmt

# Run tests
make go-test

# Check linting (Go code)
make go-lint

# Check YAML files (Bento configs)
make yaml-lint

# Validate Bento configs
make bento-lint

# Run all checks (before commit)
make go-check
```

### Before Committing

```bash
# Run full check suite
make go-check

# Output:
# ✅ gofmt: All files formatted
# ✅ goimports: All imports sorted
# ✅ go vet: No issues found
# ✅ golangci-lint: PASS
# ✅ gosec: No vulnerabilities
# ✅ go test: All tests passed (coverage: 85%)
```

### Before Pushing

```bash
# Simulate full CI pipeline locally
make go-ci

# Output:
# ✅ go-check: PASSED
# ✅ govulncheck: No vulnerabilities
# ✅ trivy fs: No HIGH/CRITICAL issues
# ✅ All CI checks passed!
```

### Before Creating PR

```bash
# Full security scan
make security-scan

# Build and scan Docker image
docker build -t inbound-parsers:dev .
make trivy-image

# Final check
make go-ci
```

---

## CI/CD Pipeline

### Pipeline Stages

```
┌─────────────────────────────────────────────────┐
│ Stage 1: Code Quality (golangci-lint)          │
│  - gofmt check                                  │
│  - goimports check                              │
│  - 50+ linters                                  │
│  - Duration: ~1-2 minutes                       │
├─────────────────────────────────────────────────┤
│ Stage 2: Security Scanning                     │
│  - gosec (source code)                          │
│  - govulncheck (Go dependencies)                │
│  - trivy fs (filesystem)                        │
│  - detect-secrets (secrets)                     │
│  - Duration: ~2-3 minutes                       │
├─────────────────────────────────────────────────┤
│ Stage 3: Testing                               │
│  - go test (unit tests)                         │
│  - Coverage report                              │
│  - Fail if coverage < 80%                       │
│  - Duration: ~1-2 minutes                       │
├─────────────────────────────────────────────────┤
│ Stage 4: Build                                 │
│  - go build (compile)                           │
│  - docker build (container)                     │
│  - Duration: ~2-3 minutes                       │
├─────────────────────────────────────────────────┤
│ Stage 5: Container Security                    │
│  - trivy image scan                             │
│  - trivy config scan (Dockerfile)               │
│  - Duration: ~1-2 minutes                       │
└─────────────────────────────────────────────────┘

Total CI time: ~7-13 minutes (vs 15-20 mins with Python)
```

### CI Success Criteria

All must pass for PR to merge:

- ✅ Code formatted with gofmt/goimports
- ✅ Zero linting warnings (golangci-lint)
- ✅ Zero security issues (gosec, trivy)
- ✅ Zero vulnerabilities (govulncheck)
- ✅ All tests passing
- ✅ Coverage ≥ 80%
- ✅ Build succeeds
- ✅ Docker image has no HIGH/CRITICAL CVEs

---

## Security Stack

### Multi-Layer Security Scanning

```
┌─────────────────────────────────────────────────┐
│ Layer 1: Source Code (gosec)                   │
│  What: Go code vulnerabilities                  │
│  Finds: SQL injection, hardcoded secrets, etc.  │
│  When: Pre-commit, CI                           │
├─────────────────────────────────────────────────┤
│ Layer 2: Dependencies (govulncheck)            │
│  What: Go module CVEs                           │
│  Finds: Known vulnerabilities in go.mod         │
│  When: Daily, CI                                │
├─────────────────────────────────────────────────┤
│ Layer 3: Dependencies (trivy)                  │
│  What: All dependencies (broader than govuln)   │
│  Finds: CVEs in Go, OS packages, etc.           │
│  When: Daily, CI                                │
├─────────────────────────────────────────────────┤
│ Layer 4: Secrets (detect-secrets)              │
│  What: Leaked credentials                       │
│  Finds: API keys, tokens, passwords             │
│  When: Pre-commit, CI                           │
├─────────────────────────────────────────────────┤
│ Layer 5: Container (trivy image)               │
│  What: Docker image vulnerabilities             │
│  Finds: OS CVEs, app CVEs, misconfigs           │
│  When: Pre-push, CI                             │
├─────────────────────────────────────────────────┤
│ Layer 6: Config (trivy config)                 │
│  What: Dockerfile, K8s, Terraform               │
│  Finds: Security misconfigurations              │
│  When: Pre-push, CI                             │
└─────────────────────────────────────────────────┘
```

### Security Scanning Commands

```bash
# Source code security
make go-sec            # Run gosec

# Dependency vulnerabilities
make go-vuln           # Run govulncheck
make trivy-fs          # Run Trivy filesystem scan

# Container security
make trivy-image       # Scan Docker image
make trivy-config      # Check Dockerfile/K8s

# All security scans
make security-scan     # Run all source + dependency scans
make docker-security   # Run all container scans
```

### Trivy Scan Types

```bash
# 1. Filesystem scan (local development)
trivy fs --severity HIGH,CRITICAL .

# 2. Docker image scan (before push)
trivy image --severity HIGH,CRITICAL inbound-parsers:latest

# 3. Configuration scan (Dockerfile, K8s)
trivy config .

# 4. Git repository scan (secrets in history)
trivy repo .

# 5. Go module scan (specific to go.mod)
trivy fs --scanners vuln go.mod
```

### Security Report Example

```bash
$ make security-scan

Running gosec...
✅ No issues found

Running govulncheck...
✅ No vulnerabilities found

Running Trivy filesystem scan...
┌─────────────────────────────────────┬──────────┬─────────┐
│ Library                             │ Severity │ CVE     │
├─────────────────────────────────────┼──────────┼─────────┤
│ github.com/example/vulnerable-lib   │ HIGH     │ CVE-... │
└─────────────────────────────────────┴──────────┴─────────┘

❌ Security scan FAILED
Action required: Update github.com/example/vulnerable-lib
```

---

## Dependency Management

### Renovate - Automated Dependency Updates

**What it does:**
- Scans `go.mod` for outdated dependencies
- Creates PRs with updates
- Groups minor/patch updates (less noise)
- Auto-merges safe updates if CI passes
- Alerts on security vulnerabilities

**Update schedule:**
- **Monday 6am:** Regular dependency updates
- **Any time:** Security vulnerability patches
- **First Monday of month:** Lock file maintenance

### Update Strategy

| Update Type | Renovate Behavior | Example |
|-------------|-------------------|---------|
| **Patch** (1.2.3 → 1.2.4) | Auto-merge if CI green | Bug fixes |
| **Minor** (1.2.0 → 1.3.0) | Auto-merge if CI green | New features |
| **Major** (1.x → 2.x) | Manual review required | Breaking changes |
| **Security** | Immediate PR, auto-merge | CVE fixes |
| **Core deps** (Bento, DKIM) | Manual review required | Critical libs |

### Renovate PR Example

```
Title: Update Go dependencies (non-major)

This PR updates the following dependencies:
- github.com/prometheus/client_golang: 1.19.0 → 1.20.0
- github.com/stretchr/testify: 1.8.4 → 1.9.0

---
✅ golangci-lint: PASSED
✅ go test: PASSED (coverage: 85%)
✅ gosec: No issues
✅ trivy: No HIGH/CRITICAL vulnerabilities

Auto-merging in 5 minutes if no objections...
```

### Managing Renovate

```bash
# Validate Renovate config
make renovate-validate

# Dry run locally (see what would update)
make renovate-dry-run

# Pause all updates (emergency)
# Add to renovate.json: "enabled": false

# Pause specific package
# Add to renovate.json: "ignoreDeps": ["package-name"]
```

### Dependency Dashboard

Renovate creates an issue in your repo:

```
📊 Dependency Dashboard

Open PRs
 - Update github.com/warpstreamlabs/bento to v1.6.0 (major)
 - Update Dockerfile alpine to 3.20

Pending Approval
 - Update github.com/emersion/go-msgauth to v0.7.0 (security)

Rate Limited
 - Waiting for Monday 6am schedule

Closed This Week
 - ✅ Update Go dependencies (non-major) - auto-merged
 - ✅ Update GitHub Actions
```

---

## Makefile Reference

### Complete Makefile Targets

```makefile
# Setup
make go-setup          # Install all Go tools
make go-verify         # Verify tools installed

# Formatting
make go-fmt            # Format code (gofmt + goimports)

# Linting
make go-lint           # Run golangci-lint
make go-vet            # Run go vet

# Testing
make go-test           # Run tests with coverage
make go-test-verbose   # Run tests with verbose output

# Security
make go-sec            # Run gosec
make go-vuln           # Run govulncheck
make trivy-fs          # Trivy filesystem scan
make trivy-image       # Trivy Docker image scan
make trivy-config      # Trivy config scan

# Combined checks
make go-check          # Format + lint + vet + test
make security-scan     # All security scans
make docker-security   # Docker-specific security
make go-ci             # Full CI simulation

# Renovate
make renovate-validate # Validate renovate.json
make renovate-dry-run  # Test Renovate locally

# Docker
make docker-build      # Build Docker image
make docker-scan       # Build + scan with Trivy
```

---

## Configuration Files Reference

### 1. `.golangci.yml`

See separate file: `.golangci.yml` in repo root

Key sections:
- `linters.enable` - Which linters to run
- `linters-settings` - Configure each linter
- `issues.exclude-rules` - Ignore specific warnings

### 2. `.trivy.yaml`

See separate file: `.trivy.yaml` in repo root

Key sections:
- `scan.skip-dirs` - Directories to skip
- `vulnerability.severity` - Only HIGH/CRITICAL
- `secret.skip-paths` - Skip test files

### 3. `renovate.json`

See separate file: `renovate.json` in repo root

Key sections:
- `packageRules` - Update strategies per package type
- `schedule` - When to create PRs
- `automerge` - Auto-merge rules

### 4. `.pre-commit-config.yaml`

See separate file: `.pre-commit-config.yaml` in repo root

Runs before each commit:
- Go formatting
- Go imports
- Go vet
- golangci-lint
- gosec
- detect-secrets

### 5. `.github/workflows/ci.yml`

See separate file: `.github/workflows/ci.yml`

CI jobs:
- lint
- security
- test
- build
- docker-security

---

## Troubleshooting

### golangci-lint Issues

**Problem:** Too slow

```bash
# Solution: Enable cache
golangci-lint cache clean
golangci-lint run --timeout 5m

# Or: Reduce linters
# Edit .golangci.yml, disable slow linters
```

**Problem:** Too many warnings

```bash
# Solution 1: Fix them (recommended)
golangci-lint run --fix

# Solution 2: Exclude specific warnings
# Edit .golangci.yml: issues.exclude-rules
```

### Trivy Issues

**Problem:** Trivy database outdated

```bash
# Solution: Update database
trivy image --download-db-only
```

**Problem:** False positives

```bash
# Solution: Add to .trivyignore
echo "CVE-2023-12345" >> .trivyignore
# With comment explaining why
```

**Problem:** Container scan too slow

```bash
# Solution: Use --light mode
trivy image --light inbound-parsers:latest
```

### Renovate Issues

**Problem:** Too many PRs

```bash
# Solution: Increase grouping in renovate.json
{
  "packageRules": [
    {
      "groupName": "all non-major dependencies",
      "matchUpdateTypes": ["minor", "patch"]
    }
  ]
}
```

**Problem:** Auto-merge not working

```bash
# Check: Branch protection rules
# GitHub Settings → Branches → main
# ✅ "Require status checks to pass"
# ✅ "Require branches to be up to date"
```

### Pre-commit Hook Issues

**Problem:** Hooks not running

```bash
# Solution: Reinstall hooks
pre-commit uninstall
pre-commit install
```

**Problem:** Hook failing

```bash
# Run manually to debug
pre-commit run --all-files golangci-lint
```

---

## Migration Checklist

**Phase 0: Setup Tooling (Week 0)**

- [ ] Install Go 1.21+
- [ ] Run `make go-setup` to install tools
- [ ] Create `.golangci.yml`
- [ ] Create `.trivy.yaml`
- [ ] Create `renovate.json`
- [ ] Update `.pre-commit-config.yaml`
- [ ] Update `.github/workflows/ci.yml`
- [ ] Update `Makefile` with Go commands
- [ ] Run `make go-verify` to confirm setup
- [ ] Initialize `.secrets.baseline`
- [ ] Enable Renovate GitHub App
- [ ] Test full pipeline: `make go-ci`

**Phase 1: First Go Code (Week 1)**

- [ ] Initialize `go.mod`
- [ ] Write first Go parser (`parsers/fbl/parser.go`)
- [ ] Write first test (`parsers/fbl/parser_test.go`)
- [ ] Run `make go-check` - should pass
- [ ] Run `make security-scan` - should pass
- [ ] Commit with pre-commit hooks enabled
- [ ] Push and verify CI passes

**Phase 2: Remove Python (Week 2-3)**

- [ ] All Go parsers implemented
- [ ] All tests passing (coverage ≥ 80%)
- [ ] Security scans clean
- [ ] Delete `pyproject.toml`
- [ ] Delete Python parser files
- [ ] Update Dockerfile (Go only)
- [ ] Remove Python from CI
- [ ] Remove Python pre-commit hooks
- [ ] Update README.md

---

## Quick Reference

### Most Common Commands

```bash
# Daily development
make go-fmt go-test      # Format + test

# Before commit
make go-check            # All checks

# Before push
make go-ci               # Full CI

# Security scan
make security-scan       # All security tools

# Docker workflow
docker build -t inbound-parsers:dev .
make trivy-image
```

### Tool Cheat Sheet

| Task | Command | When |
|------|---------|------|
| Format | `make go-fmt` | Every save |
| Lint | `make go-lint` | Pre-commit |
| Test | `make go-test` | Pre-commit |
| Security | `make go-sec` | Pre-commit |
| Vulnerabilities | `make go-vuln` | Daily |
| Container scan | `make trivy-image` | Pre-push |
| Full check | `make go-check` | Pre-commit |
| CI simulation | `make go-ci` | Pre-push |

---

## Resources

### Documentation

- **golangci-lint:** https://golangci-lint.run/
- **Trivy:** https://aquasecurity.github.io/trivy/
- **Renovate:** https://docs.renovatebot.com/
- **gosec:** https://github.com/securego/gosec
- **Go testing:** https://pkg.go.dev/testing

### GitHub Repos

- golangci-lint: https://github.com/golangci/golangci-lint
- Trivy: https://github.com/aquasecurity/trivy
- Renovate: https://github.com/renovatebot/renovate
- gosec: https://github.com/securego/gosec
- govulncheck: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck

### Community

- Go security: https://go.dev/security/
- Trivy community: https://slack.aquasec.com/
- Renovate discussions: https://github.com/renovatebot/renovate/discussions

---

**Last Updated:** 2025-10-18
**Status:** ✅ Ready for implementation
**Next Step:** Create configuration files and run `make go-setup`
