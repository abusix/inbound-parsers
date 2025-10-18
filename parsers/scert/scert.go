package scert

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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	event := events.NewEvent("scert")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Set IP from subject
	event.IP = subject

	// Find URL in body
	url := common.FindString(body, "http", "\n")
	if url != "" {
		event.URL = strings.TrimSpace(url)
	}

	// Determine event type from subject
	var eventType events.EventType
	if strings.Contains(subject, "PHISHING") {
		eventType = events.NewPhishing()
	} else if strings.Contains(subject, "MALWARE") {
		eventType = events.NewMalwareHosting()
	} else {
		// No matching event type, return empty list
		return []*events.Event{}, nil
	}
	event.EventTypes = []events.EventType{eventType}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
