// Package ttp_law implements the TTP Law parser for illegal advertisement reports
package ttp_law

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the TTP Law parser
type Parser struct{}

// Parse parses emails from @ttp-law.com reporting illegal advertisements
// The parser extracts URLs from Japanese or English format emails
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("ttp_law")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewIllegalAdvertisement()}

	// Extract URL - check for English format first, then Japanese format
	var url string
	if strings.Contains(body, "Webpage URL:") {
		url = common.FindStringWithoutMarkers(body, "Webpage URL:", "---")
	} else {
		// Japanese format: 違反ページURL:
		url = common.FindStringWithoutMarkers(body, "違反ページURL:", "---")
	}

	if url != "" {
		event.URL = strings.TrimSpace(url)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
