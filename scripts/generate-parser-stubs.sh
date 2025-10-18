#!/bin/bash
# Generate Go parser stubs for all Python parsers
# This script creates minimal parser implementations that compile but return "not implemented"

set -e

# Source directory with Python parsers
PYTHON_PARSERS="/tmp/abusix-parsers-old/abusix_parsers/parsers/parser"
# Target directory for Go parsers
GO_PARSERS="./parsers"

# Get list of all parser files (excluding __init__.py and special files)
find "$PYTHON_PARSERS" -name "*.py" ! -name "__init__.py" | sort | while read -r pyfile; do
    # Extract parser name from filename
    filename=$(basename "$pyfile" .py)

    # Clean parser name (remove priority prefixes)
    clean_name=$(echo "$filename" | sed 's/^[0-9]*_//; s/^ZX_//; s/^ZY_//; s/^ZZ_//')

    # Convert to Go package name (lowercase, replace hyphens with underscores)
    package_name=$(echo "$clean_name" | tr '[:upper:]' '[:lower:]' | tr '-' '_')

    # Create parser directory
    parser_dir="$GO_PARSERS/$package_name"
    mkdir -p "$parser_dir"

    # Generate Go file
    go_file="$parser_dir/${package_name}.go"

    echo "Generating stub for $clean_name -> $go_file"

    cat > "$go_file" <<EOF
// Package $package_name implements the $clean_name parser
// AUTO-GENERATED STUB - Needs implementation from Python version
package $package_name

import (
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/pkg/email"
)

const (
	ParserName = "$clean_name"
)

// ${clean_name^}Parser implements the $clean_name parser
type Parser struct {
	*base.BaseParser
}

// New creates a new $clean_name parser instance
func New(serializedEmail email.SerializedEmail, fromAddr, fromName, contentType string) *Parser {
	bp := base.NewBaseParser(serializedEmail, fromAddr, fromName, contentType)
	bp.ParserName = ParserName

	return &Parser{
		BaseParser: bp,
	}
}

// Match determines if this parser should handle the email
// TODO: Implement matching logic from Python version
func (p *Parser) Match() base.MatchResult {
	return base.MatchIgnore // TODO: Implement from $filename
}

// Parse processes the email and yields events
// TODO: Implement full parsing logic from Python version
func (p *Parser) Parse() ([]events.Event, error) {
	// TODO: Port logic from $filename
	return nil, &base.ParserError{Message: "Parser $clean_name not yet implemented"}
}

// Rewrite optionally rewrites the email data
func (p *Parser) Rewrite() map[string]interface{} {
	return make(map[string]interface{})
}
EOF

done

echo ""
echo "✅ Generated stubs for all parsers!"
echo ""
echo "Next steps:"
echo "1. Run 'go mod tidy' to ensure all packages compile"
echo "2. Implement high-priority parsers (shadowserver, cert_*, etc.)"
echo "3. Update cmd/bento-parsers/main.go to register all parsers"
