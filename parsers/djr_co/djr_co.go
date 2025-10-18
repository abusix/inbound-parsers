package djr_co

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
	bodyLower := strings.ToLower(body)

	// Check if this is a spam report
	if !strings.Contains(bodyLower, "spam") {
		return nil, common.NewNewTypeError(subject)
	}

	event := events.NewEvent("djr_co")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract IP from received block
	// Python: received_block = find_string(body_lower, 'received: 	from', ';')
	// Python: event.ip = find_string_without_markers(received_block, '[', ']')
	receivedBlock := common.FindString(bodyLower, "received: \tfrom", ";")
	if receivedBlock != "" {
		ip := common.FindStringWithoutMarkers(receivedBlock, "[", "]")
		if validIP := common.IsIP(ip); validIP != "" {
			event.IP = validIP
		}
	}

	// Extract event date
	// Python: event.event_date = find_string_without_markers(body_lower, 'delivery-date:')
	eventDateStr := common.FindStringWithoutMarkers(bodyLower, "delivery-date:", "")
	if eventDateStr != "" {
		eventDate := email.ParseDate(strings.TrimSpace(eventDateStr))
		event.EventDate = eventDate
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
