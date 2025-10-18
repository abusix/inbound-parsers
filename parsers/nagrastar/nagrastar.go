// Package nagrastar implements the nagrastar.com parser
package nagrastar

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the nagrastar.com parser
type Parser struct{}

// Parse parses emails from @nagrastar.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Extract copyright owner: text between "members of the" and "("
	copyrightOwner := strings.TrimSpace(common.FindStringWithoutMarkers(body, "members of the", "("))

	// Get event date from email headers
	dateStr := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}
	eventDate := email.ParseDate(dateStr)

	// Extract URLs from block after "video url"
	// Python: body.lower().replace('page ', '')
	bodyLower := strings.ToLower(body)
	bodyLower = strings.ReplaceAll(bodyLower, "page ", "")

	urls := common.GetBlockAfterWithStop(bodyLower, "video url", "")

	var eventList []*events.Event
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		event := events.NewEvent("nagrastar")
		event.EventDate = eventDate
		event.URL = url

		// Add Copyright event type
		event.EventTypes = []events.EventType{
			events.NewCopyright(url, copyrightOwner, ""),
		}

		eventList = append(eventList, event)
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
