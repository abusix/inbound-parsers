#!/bin/bash
set -euo pipefail

# Quick verification script for parser mapping
# Usage: ./scripts/verify-mapping.sh

echo "========================================="
echo "PARSER MAPPING VERIFICATION"
echo "========================================="
echo ""

PYTHON_DIR="/tmp/abusix-parsers-old/abusix_parsers/parsers/parser"
GO_DIR="/Users/tknecht/Projects/inbound-parsers/parsers"

echo "Python source: $PYTHON_DIR"
echo "Go target: $GO_DIR"
echo ""

# Count Python parsers
PYTHON_COUNT=$(find "$PYTHON_DIR" -name "*.py" ! -name "__init__.py" | wc -l | tr -d ' ')
echo "Python parsers: $PYTHON_COUNT"

# Count Go parsers (excluding base, common)
GO_COUNT=$(find "$GO_DIR" -mindepth 1 -maxdepth 1 -type d ! -name "base" ! -name "common" | wc -l | tr -d ' ')
echo "Go parsers: $GO_COUNT"

echo ""
echo "Target: 477 parsers in both Python and Go"
echo ""

if [ "$PYTHON_COUNT" -eq 477 ]; then
    echo "✅ Python count is correct (477)"
else
    echo "❌ Python count is WRONG (expected 477, got $PYTHON_COUNT)"
fi

if [ "$GO_COUNT" -eq 477 ]; then
    echo "✅ Go count is correct (477) - PERFECT PARITY!"
elif [ "$GO_COUNT" -eq 550 ]; then
    echo "⚠️  Go count has 73 extra parsers - cleanup needed"
else
    echo "❌ Go count is unexpected (got $GO_COUNT)"
fi

echo ""
echo "========================================="
echo "QUICK ACTIONS"
echo "========================================="
echo ""

if [ "$GO_COUNT" -eq 550 ]; then
    echo "To delete 73 extra parsers:"
    echo "  ./scripts/delete-extra-parsers.sh"
    echo ""
    echo "To analyze mapping:"
    echo "  go run scripts/map-parsers.go"
    echo ""
elif [ "$GO_COUNT" -eq 477 ]; then
    echo "🎉 PERFECT! 1:1 parity achieved!"
    echo ""
    echo "Verify mapping:"
    echo "  go run scripts/map-parsers.go"
    echo ""
fi
