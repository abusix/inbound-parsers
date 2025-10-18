package icscards

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
	bodyLower := strings.ToLower(body)

	// Check if this is the fraudulent website type
	if !strings.Contains(bodyLower, "fraudulent website(s)") {
		return nil, common.NewNewTypeError(serializedEmail.Identifier)
	}

	// Get date from headers
	var dateFallback string
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		dateFallback = dateHeader[0]
	}

	// Create event template
	eventTemplate := events.NewEvent("icscards")
	eventTemplate.EventDate = email.ParseDate(dateFallback)
	eventTemplate.EventTypes = []events.EventType{
		events.NewFraud(),
	}

	// Extract URL block after the marker
	urlBlock := common.GetBlockAfterWithStop(bodyLower, "the following fraudulent website(s):", "")

	var results []*events.Event
	for _, urlLine := range urlBlock {
		urlLine = strings.TrimSpace(urlLine)
		if urlLine == "" {
			continue
		}

		// Replace obfuscation
		urlLine = strings.ReplaceAll(urlLine, "htXtp", "http")

		// Process URL
		processedURL, err := common.ProcessURL(urlLine)
		if err != nil {
			// Skip invalid URLs (similar to Python's pass in except ValueError)
			continue
		}

		// Create a copy of the event template
		eventCopy := *eventTemplate
		// Copy the event types slice
		eventCopy.EventTypes = make([]events.EventType, len(eventTemplate.EventTypes))
		copy(eventCopy.EventTypes, eventTemplate.EventTypes)

		eventCopy.URL = processedURL
		results = append(results, &eventCopy)
	}

	if len(results) == 0 {
		return nil, common.NewParserError("no valid URLs found")
	}

	return results, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
