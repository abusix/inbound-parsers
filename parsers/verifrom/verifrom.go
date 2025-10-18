package verifrom

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse implements a rewrite parser for verifrom.com emails
// This parser checks if the email is from @verifrom.com and contains "x-arf" in the body
// If so, it adds a "x-xarf: plain" header to the email
// This is a rewrite-only parser, so it returns an empty events list
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get the From address
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil || fromAddr == "" {
		return nil, nil // Ignore if no From address
	}

	// Check if email is from @verifrom.com
	if !strings.HasSuffix(fromAddr, "@verifrom.com") {
		return nil, nil // Ignore if not from verifrom.com
	}

	// Get the body and convert to lowercase for case-insensitive search
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, nil // Ignore if no body
	}
	bodyLower := strings.ToLower(body)

	// Check if body contains "x-arf"
	if !strings.Contains(bodyLower, "x-arf") {
		return nil, nil // Ignore if no x-arf in body
	}

	// Rewrite: Add x-xarf header with value "plain"
	if serializedEmail.Headers == nil {
		serializedEmail.Headers = make(map[string][]string)
	}
	serializedEmail.Headers["x-xarf"] = []string{"plain"}

	// Return empty events list (this is a rewrite-only parser)
	return nil, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
