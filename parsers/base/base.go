// Package base provides base parser types and utilities
package base

import (
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser is the interface that all parsers must implement
type Parser interface {
	Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error)
	GetPriority() int
}

// Priority constants define the execution order of parsers.
// Lower numbers run first (higher priority).
const (
	// PriorityPreprocessor (001-002) - Preprocessing parsers that must run FIRST
	// Examples: mail_reject, simple_rewrite
	PriorityPreprocessor = 1

	// PriorityFormat (01-06) - Standard format parsers
	// Examples: marf, xarf, feedback_loop, gold_parser, simple_url_report
	PriorityFormat = 10

	// PriorityVendor (default) - Vendor-specific parsers (alphabetically)
	// Examples: abusix, amazon, cloudflare, etc.
	PriorityVendor = 100

	// PriorityFallbackZX - First fallback tier (ZX_*)
	// Example: generic_spam_trap
	PriorityFallbackZX = 1000

	// PriorityFallbackZY - Second fallback tier (ZY_*)
	// Example: simple_format
	PriorityFallbackZY = 2000

	// PriorityFallbackZZ - Last resort fallback tier (ZZ_*)
	// Example: simple_guess_parser
	PriorityFallbackZZ = 9999
)

// BaseParser provides common functionality for all parsers
type BaseParser struct {
	Name     string
	Priority int
}

// NewBaseParser creates a new base parser with the given name and default vendor priority
func NewBaseParser(name string) BaseParser {
	return BaseParser{
		Name:     name,
		Priority: PriorityVendor, // Default to vendor priority
	}
}

// NewBaseParserWithPriority creates a new base parser with the given name and priority
func NewBaseParserWithPriority(name string, priority int) BaseParser {
	return BaseParser{
		Name:     name,
		Priority: priority,
	}
}

// GetName returns the parser name
func (p *BaseParser) GetName() string {
	return p.Name
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *BaseParser) GetPriority() int {
	return p.Priority
}
