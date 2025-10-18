// Package nwf implements the NWF parser for copyright infringement reports
package nwf

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the NWF parser
type Parser struct{}

// Parse parses emails from @nwf.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)

	// Check if this is a copyright complaint
	if !strings.Contains(subjectLower, "copyright") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Create event
	event := events.NewEvent("nwf")

	// Set event date from headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}
	}

	// Extract original work
	originalWork := common.GetNonEmptyLineAfter(body, "Original Work :")

	// Create copyright event type
	copyright := &events.Copyright{
		BaseEventType: events.BaseEventType{
			Name: "copyright",
			Type: "copyright",
		},
		CopyrightedWork: originalWork,
	}
	event.EventTypes = []events.EventType{copyright}

	// Extract infringing URL
	event.URL = common.GetNonEmptyLineAfter(body, "content that you believe is infringing:")

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
