package takedownnow

import (
	"fmt"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Set event_date from email headers
	var eventsList []*events.Event

	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "phishing") {
		event := events.NewEvent("takedownnow")

		// Set event date from email headers
		if serializedEmail.Headers != nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}
		}

		// Set event type
		event.EventTypes = []events.EventType{events.NewPhishing()}

		// Extract URL from body
		event.URL = common.FindStringWithoutMarkers(body, "website hosted at:", "")

		// Extract IP from body
		event.IP = common.FindStringWithoutMarkers(body, "website hosted at:", "Dear")

		// Extract port from body
		portStr := common.FindStringWithoutMarkers(body, "Porta:", "")
		if portStr != "" {
			if port, err := common.ParsePort(portStr); err == nil {
				event.Port = port
			}
		}

		eventsList = append(eventsList, event)
		return eventsList, nil
	}

	// If subject doesn't contain "phishing", raise an error
	return nil, fmt.Errorf("unknown subject type: %s", subjectLower)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
