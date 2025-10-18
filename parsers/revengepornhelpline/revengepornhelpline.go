// Package revengepornhelpline implements the revengepornhelpline.org.uk parser
package revengepornhelpline

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the revengepornhelpline parser
type Parser struct{}

// NewParser creates a new revengepornhelpline parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from help@revengepornhelpline.org.uk
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Replace 'Thank you in advance' with 'Kind Regards' to normalize end marker
	body = strings.ReplaceAll(body, "Thank you in advance", "Kind Regards")

	// Get event date from headers
	eventDate := email.ParseDate("")
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract entry block between markers
	entryBlock := common.FindStringWithoutMarkers(body, "for removal:", "Kind Regards")

	var result []*events.Event

	// Process each line looking for URLs
	for _, line := range strings.Split(entryBlock, "\n") {
		line = strings.TrimSpace(line)
		if common.IsURL(line) {
			event := events.NewEvent("revengepornhelpline")
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
			event.URL = line
			result = append(result, event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
