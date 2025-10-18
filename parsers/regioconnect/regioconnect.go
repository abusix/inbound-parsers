// Package regioconnect implements the regioconnect.net parser
package regioconnect

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the regioconnect parser
type Parser struct{}

// Parse parses emails from @regioconnect.net
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Create event
	event := events.NewEvent("regioconnect")

	// Determine event type from body content
	if strings.Contains(bodyLower, "spam") {
		event.EventTypes = []events.EventType{events.NewSpam()}
	} else if strings.Contains(bodyLower, "phishing") {
		event.EventTypes = []events.EventType{events.NewPhishing()}
	} else {
		// Unknown type - need to identify the type from the email
		subject, _ := common.GetSubject(serializedEmail, false)
		return nil, common.NewNewTypeError(subject)
	}

	// Try to extract event date from body
	dateStr := common.FindStringWithoutMarkers(body, "Date:", "")
	if dateStr != "" {
		eventDate := email.ParseDate(strings.TrimSpace(dateStr))
		event.EventDate = eventDate
	} else {
		// Fall back to email header date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}
	}

	// Extract IP from Received: field
	ip := common.FindStringWithoutMarkers(body, "Received:", "")
	if ip != "" {
		event.IP = strings.TrimSpace(ip)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
