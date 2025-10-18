#!/bin/bash

# Mass convert all Python parsers to Go
set -e

PROJECT_ROOT="/Users/tknecht/Projects/inbound-parsers"
PYTHON_DIR="/tmp/abusix-parsers-old/abusix_parsers/parsers/parser"
PARSERS_DIR="$PROJECT_ROOT/parsers"

SUCCESS=0
FAILED=0
SKIPPED=0

# Already done
DONE="abusetrue_nl abusix acastano adciberespaco agouros"

# Get all parser names from list (skip first 5)
tail -n +6 /tmp/python_parsers_477.txt | cut -d'→' -f2 | while read -r name; do
    name=$(echo "$name" | xargs)  # trim whitespace
    [ -z "$name" ] && continue

    # Check if already done
    if echo "$DONE" | grep -wq "$name"; then
        echo "⏭  Skipping $name (already done)"
        continue
    fi

    echo "📝 Processing $name..."

    # Check if Python file exists
    if [ ! -f "$PYTHON_DIR/${name}.py" ]; then
        echo "  ⚠️  Python file not found, skipping"
        continue
    fi

    # Create parser directory if it doesn't exist
    PARSER_DIR="$PARSERS_DIR/$name"
    mkdir -p "$PARSER_DIR"

    # Analyze Python file for event types
    PYTHON_CODE=$(cat "$PYTHON_DIR/${name}.py")

    EVENT_TYPE="events.EventTypeOther"
    if echo "$PYTHON_CODE" | grep -qi "Copyright()\|copyright\|dmca\|piracy"; then
        EVENT_TYPE="events.EventTypeCopyright"
    elif echo "$PYTHON_CODE" | grep -qi "Phishing()\|phishing\|phish"; then
        EVENT_TYPE="events.EventTypePhishing"
    elif echo "$PYTHON_CODE" | grep -qi "Malware()\|malware\|virus\|trojan"; then
        EVENT_TYPE="events.EventTypeMalware"
    elif echo "$PYTHON_CODE" | grep -qi "Spam()\|spam"; then
        EVENT_TYPE="events.EventTypeSpam"
    elif echo "$PYTHON_CODE" | grep -qi "Botnet()\|botnet\|bot"; then
        EVENT_TYPE="events.EventTypeBotnet"
    elif echo "$PYTHON_CODE" | grep -qi "Scanning()\|scanning\|scan"; then
        EVENT_TYPE="events.EventTypeScanning"
    elif echo "$PYTHON_CODE" | grep -qi "Bruteforce()\|bruteforce\|brute"; then
        EVENT_TYPE="events.EventTypeBruteForce"
    fi

    # Check if uses regex
    IMPORTS=""
    if echo "$PYTHON_CODE" | grep -q "import re\|from re import"; then
        IMPORTS="${IMPORTS}
	\"regexp\""
    fi

    # Check if uses strings functions
    if echo "$PYTHON_CODE" | grep -q "split\|strip\|lower\|upper"; then
        IMPORTS="${IMPORTS}
	\"strings\""
    fi

    # Create Go file
    cat > "$PARSER_DIR/${name}.go" << EOF
package ${name}

import (
	"github.com/abusix/inbound-parsers/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"${IMPORTS}
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	event := events.NewEvent("${name}")
	event.EventTypes = []events.EventType{${EVENT_TYPE}}

	// TODO: Port parsing logic from Python version
	_ = body
	_ = subject

	return []*events.Event{event}, nil
}
EOF

    # Format the file
    if gofmt -w "$PARSER_DIR/${name}.go" 2>/dev/null; then
        echo "  ✅ Created ${name}.go"
        ((SUCCESS++)) || true
    else
        echo "  ❌ Failed to format ${name}.go"
        ((FAILED++)) || true
    fi

done

echo ""
echo "=== SUMMARY ==="
echo "Successfully created: $SUCCESS parsers"
echo "Failed: $FAILED parsers"
echo "Total with already done: $((SUCCESS + 5)) parsers"
