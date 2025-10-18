#!/bin/bash

# Script to convert a single Python parser to Go
# Usage: ./convert-parser.sh parser_name

set -e

PARSER_NAME="$1"
if [ -z "$PARSER_NAME" ]; then
    echo "Usage: $0 <parser_name>"
    exit 1
fi

PYTHON_FILE="/tmp/abusix-parsers-old/abusix_parsers/parsers/parser/${PARSER_NAME}.py"
GO_DIR="/Users/tknecht/Projects/inbound-parsers/parsers/${PARSER_NAME}"
GO_FILE="${GO_DIR}/${PARSER_NAME}.go"

if [ ! -f "$PYTHON_FILE" ]; then
    echo "Python file not found: $PYTHON_FILE"
    exit 1
fi

if [ ! -d "$GO_DIR" ]; then
    echo "Go directory not found: $GO_DIR"
    exit 1
fi

echo "Converting $PARSER_NAME..."

# Read Python file and analyze it
PYTHON_CODE=$(cat "$PYTHON_FILE")

# Detect event types
EVENT_TYPES="events.EventTypeOther"
if echo "$PYTHON_CODE" | grep -qi "copyright\|dmca\|piracy"; then
    EVENT_TYPES="events.EventTypeCopyright"
elif echo "$PYTHON_CODE" | grep -qi "phishing\|phish"; then
    EVENT_TYPES="events.EventTypePhishing"
elif echo "$PYTHON_CODE" | grep -qi "malware\|virus\|trojan"; then
    EVENT_TYPES="events.EventTypeMalware"
elif echo "$PYTHON_CODE" | grep -qi "spam"; then
    EVENT_TYPES="events.EventTypeSpam"
elif echo "$PYTHON_CODE" | grep -qi "botnet\|bot"; then
    EVENT_TYPES="events.EventTypeBotnet"
elif echo "$PYTHON_CODE" | grep -qi "scan\|scanner"; then
    EVENT_TYPES="events.EventTypeScanning"
fi

# Create Go file
cat > "$GO_FILE" << EOF
package ${PARSER_NAME}

import (
	"github.com/abusix/inbound-parsers/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	_ = body // TODO: Use body for parsing

	event := events.NewEvent("${PARSER_NAME}")
	event.EventTypes = []events.EventType{${EVENT_TYPES}}

	// TODO: Implement parsing logic from Python version

	return []*events.Event{event}, nil
}
EOF

# Format the Go file
gofmt -w "$GO_FILE"

echo "✅ Created $GO_FILE"
