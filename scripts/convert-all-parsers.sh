#!/bin/bash

# Script to convert all remaining Python parsers to Go
set -e

SCRIPT_DIR="/Users/tknecht/Projects/inbound-parsers/scripts"
PARSER_LIST="/tmp/python_parsers_477.txt"

# Already completed
COMPLETED=(
    "abusetrue_nl"
    "abusix"
    "acastano"
    "adciberespaco"
    "agouros"
)

# Counters
SUCCESS=0
FAILED=0
SKIPPED=5  # Already completed

# Read and process each parser
while IFS='→' read -r num name; do
    name=$(echo "$name" | tr -d '[:space:]')
    [ -z "$name" ] && continue

    # Check if already completed
    SKIP=false
    for comp in "${COMPLETED[@]}"; do
        if [ "$name" = "$comp" ]; then
            SKIP=true
            break
        fi
    done

    if $SKIP; then
        continue
    fi

    echo "[$((SKIPPED + SUCCESS + FAILED + 1))/477] Processing $name..."

    if "${SCRIPT_DIR}/convert-parser.sh" "$name" 2>&1; then
        ((SUCCESS++))
        echo "  ✅ Success"
    else
        ((FAILED++))
        echo "  ❌ Failed"
    fi

done < "$PARSER_LIST"

echo ""
echo "=== FINAL REPORT ==="
echo "Total parsers: 477"
echo "Already completed: $SKIPPED"
echo "Successfully converted: $SUCCESS"
echo "Failed: $FAILED"
echo "Total done: $((SKIPPED + SUCCESS))"
echo "Remaining: $((477 - SKIPPED - SUCCESS))"
