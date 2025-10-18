// Package d3lab implements the d3lab parser
// This is a 100% exact Go translation of Python's d3lab parser
package d3lab

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the d3lab parser
type Parser struct {
	base.BaseParser
}

// New creates a new d3lab parser instance
func New() *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("d3lab"),
	}
}

// NewParser creates a new d3lab parser instance (legacy compatibility)
func NewParser() *Parser {
	return New()
}

// Parse parses the email and returns events
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Get email body and subject
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Determine event type - must contain "Phishing"
	if !strings.Contains(body, "Phishing") {
		return nil, common.NewNewTypeError(subject)
	}

	// Create event template
	eventTemplate := events.NewEvent("d3lab")
	eventTemplate.EventDate = eventDate
	eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}

	var eventsList []*events.Event

	// Check for the specific marker for block extraction
	if strings.Contains(body, "the following addresses (remove any square brackets):") {
		// Extract event block after marker
		eventBlock := common.GetBlockAfterWithStop(body, "the following addresses (remove any square brackets):", "")

		// Process each line in the block
		for _, line := range eventBlock {
			// Create a copy of the event template
			event := copyEvent(eventTemplate)

			// Clean up obfuscation - replace [.] with .
			line = strings.ReplaceAll(line, "[.]", ".")

			// Special handling: if line starts with "http." or "https.", convert to proper URL
			if strings.HasPrefix(line, "http.") {
				line = "http://" + strings.TrimPrefix(line, "http.")
			} else if strings.HasPrefix(line, "https.") {
				line = "https://" + strings.TrimPrefix(line, "https.")
			}

			// Try to set as URL
			if common.IsURL(line) {
				event.URL = line
			}

			// Try to set as IP (mimicking Python's behavior of setting both)
			if ip := common.IsIP(line); ip != "" {
				event.IP = ip
			}

			// Only add event if it has URL or IP
			if event.URL != "" || event.IP != "" {
				eventsList = append(eventsList, event)
			}
		}

		// If no events were extracted, fall back to subject
		if len(eventsList) == 0 {
			eventTemplate.URL = subject
			eventsList = append(eventsList, eventTemplate)
		}
	} else {
		// Fallback: use subject as URL
		eventTemplate.URL = subject
		eventsList = append(eventsList, eventTemplate)
	}

	return eventsList, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent(template.Parser)
	event.EventDate = template.EventDate

	// Copy event types
	if len(template.EventTypes) > 0 {
		event.EventTypes = make([]events.EventType, len(template.EventTypes))
		for i, et := range template.EventTypes {
			event.EventTypes[i] = et
		}
	}

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
