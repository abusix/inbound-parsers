package aol

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Split body at "**********" and take the first part
	relevantBody := body
	if parts := strings.Split(body, "**********"); len(parts) > 0 {
		relevantBody = parts[0]
	}

	// Create event template
	eventTemplate := events.NewEvent("aol")

	// Determine event type based on body content
	bodyLower := strings.ToLower(relevantBody)
	if strings.Contains(bodyLower, "phish") {
		eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
	} else if strings.Contains(bodyLower, "fraud") {
		eventTemplate.EventTypes = []events.EventType{events.NewFraud()}
	} else {
		eventTemplate.EventTypes = []events.EventType{events.NewSpam()}
	}

	// Get event date from headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeader[0])
	}

	var results []*events.Event

	// Process each line in the relevant body
	for _, line := range strings.Split(relevantBody, "\n") {
		// Create a copy of the template event
		event := *eventTemplate
		event.EventTypes = make([]events.EventType, len(eventTemplate.EventTypes))
		copy(event.EventTypes, eventTemplate.EventTypes)

		// Try to extract IP
		if ip := common.ExtractOneIP(line); ip != "" {
			event.IP = ip
		}

		// Try to process URL
		if url, err := common.ProcessURL(line); err == nil && url != "" {
			// Only set URL if it's different from the IP
			if url != event.IP {
				event.URL = url
			}
		}

		// Only yield events that have either URL or IP
		if event.URL != "" || event.IP != "" {
			results = append(results, &event)
		}
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no valid events found")
	}

	return results, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
