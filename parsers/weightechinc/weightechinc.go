// Package weightechinc implements the weightechinc parser
package weightechinc

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the weightechinc parser
type Parser struct{}

// Parse parses emails from newell@weightechinc.com
// This is a 100% exact Go translation of the Python weightechinc parser
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Get date from email headers
	dateFallback := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateFallback = dateHeaders[0]
	}

	// Create event
	event := events.NewEvent("weightechinc")

	// Determine event type based on subject
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(subjectLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Set event date
	event.EventDate = email.ParseDate(dateFallback)

	// Extract IP from body using find_string_without_markers
	// In Python: find_string_without_markers(body, 'IP:')
	// This finds text after 'IP:' until the next line break
	event.IP = common.FindStringWithoutMarkers(body, "IP:", "")

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
