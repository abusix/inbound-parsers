// Package legalbaselaw implements the legalbaselaw.com parser
package legalbaselaw

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the legalbaselaw parser
type Parser struct{}

// Parse parses emails from @legalbaselaw.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get date fallback
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	// Create event
	event := events.NewEvent("legalbaselaw")

	// Set event date
	eventDate := email.ParseDate(dateFallback)
	event.EventDate = eventDate

	// Check if subject contains "trademark"
	if strings.Contains(strings.ToLower(subject), "trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Set URL to subject
	event.URL = subject

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
