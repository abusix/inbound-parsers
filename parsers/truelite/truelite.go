package truelite

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
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("no email body found")
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, common.NewParserError("no subject found")
	}

	subjectLower := strings.ToLower(subject)

	// Check if this is a spam report or abuse report
	isSpamReport := strings.Contains(subjectLower, "spam report")
	isAbuseReport := strings.Contains(subjectLower, "abuse report")

	if isSpamReport || isAbuseReport {
		event := events.NewEvent("truelite")
		event.EventTypes = []events.EventType{events.NewSpam()}

		// Extract event date from email headers
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			eventDate := email.ParseDate(dateHeader[0])
			if eventDate != nil {
				event.EventDate = eventDate
			}
		}

		// Extract IP from body between "Received: " and "]"
		// Python: event.ip = find_string_without_markers(body, 'Received: ', ']')
		ip := common.FindStringWithoutMarkers(body, "Received: ", "]")
		if ip != "" {
			event.IP = ip
		}

		return []*events.Event{event}, nil
	}

	// Unknown type - raise NewTypeError as in Python
	return nil, common.NewNewTypeError(subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
