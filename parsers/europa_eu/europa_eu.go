// Package europa_eu implements the europa_eu parser
package europa_eu

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the europa_eu parser
type Parser struct{}

// Parse parses emails from europa.eu for malicious activity reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(body, "unusual activity") {
		return nil, common.NewNewTypeError(subject)
	}

	eventTemplate := events.NewEvent("europa_eu")
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}
	eventTemplate.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	var result []*events.Event

	if strings.Contains(body, "the below IP addresses") {
		ipBlock := common.GetBlockAfterWithStop(body, "http://ec.europa.eu/taxation_customs/vies/).", "")
		for _, ipLine := range ipBlock {
			event := copyEvent(eventTemplate)
			event.IP = ipLine
			result = append(result, event)
		}
	} else {
		eventTemplate.IP = common.FindStringWithoutMarkers(body, "IP address", "registered")
		result = append(result, eventTemplate)
	}

	return result, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent("europa_eu")
	event.EventDate = template.EventDate
	event.EventTypes = make([]events.EventType, len(template.EventTypes))
	copy(event.EventTypes, template.EventTypes)
	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
