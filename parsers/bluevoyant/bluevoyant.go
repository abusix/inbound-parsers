package bluevoyant

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

	event := events.NewEvent("bluevoyant")
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Set event date from email headers
	if dateHeaders := serializedEmail.Headers["date"]; len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Check if body contains IP address or domain name
	if strings.Contains(body, `("IP address")`) {
		// Extract IP address between "IP address" and " ("
		ip := common.FindStringWithoutMarkers(body, "IP address", " (")
		ip = strings.ReplaceAll(ip, "[.]", ".")
		event.IP = ip
	} else {
		// Extract domain/URL between "domain name" and " ("
		url := common.FindStringWithoutMarkers(body, "domain name", " (")
		event.URL = url
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
