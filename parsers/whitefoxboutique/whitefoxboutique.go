// Package whitefoxboutique implements the whitefoxboutique parser
package whitefoxboutique

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the whitefoxboutique parser
type Parser struct{}

// NewParser creates a new whitefoxboutique parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from enforcement@whitefoxboutique.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Create event template
	eventTemplate := events.NewEvent("whitefoxboutique")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract external ID from Current Issue field
	externalID := common.FindStringWithoutMarkers(body, "Current Issue:", "\n")
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{
			ID: strings.TrimSpace(externalID),
		})
	}

	// Determine infringement type
	infringementType := common.FindStringWithoutMarkers(body, "Infringement type:", "\n")

	// Set event type based on infringement type
	if strings.Contains(strings.ToLower(infringementType), "copyright") || strings.Contains(bodyLower, "intellectual property rights") {
		eventTemplate.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
	} else {
		return nil, common.NewNewTypeError(infringementType)
	}

	// Extract IP
	eventTemplate.IP = common.FindStringWithoutMarkers(body, "IP address:", "\n")

	// Look for URL block after "URL(s) where illegal content is located:"
	urlsBlock := common.GetBlockAfter(body, "URL(s) where illegal content is located:")

	// Generate events for each URL
	var result []*events.Event
	for _, url := range urlsBlock {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		// Deep copy the event template
		event := events.NewEvent(eventTemplate.Parser)
		event.EventDate = eventTemplate.EventDate
		event.EventTypes = eventTemplate.EventTypes
		event.IP = eventTemplate.IP

		// Copy event details
		for _, detail := range eventTemplate.EventDetails {
			event.AddEventDetail(detail)
		}

		// Set the URL for this event
		event.URL = url

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
