// Package jutho implements the jutho.com parser
package jutho

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the jutho parser
type Parser struct{}

// NewParser creates a new jutho parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from @jutho.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Check if body contains 'spam'
	if !strings.Contains(body, "spam") {
		return nil, common.NewNewTypeError(subject)
	}

	// Create event
	event := events.NewEvent("jutho")

	// Set event type to Spam
	event.EventTypes = []events.EventType{events.NewSpam()}

	// IP is in the subject
	event.IP = subject

	// Get event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Extract URL from body: find string between 'von der Domain ' and ' '
	url := common.FindStringWithoutMarkers(body, "von der Domain ", " ")
	if url != "" {
		event.URL = url
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
