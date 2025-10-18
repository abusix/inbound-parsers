package cammodelprotect

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
	// Get body (throws=true to match Python behavior)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract copyright owner
	copyrightOwner := strings.TrimSpace(common.FindStringWithoutMarkers(body, "represents", "("))

	// Extract date from headers
	var dateStr string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}

	// Extract IP address
	bodyLower := strings.ToLower(body)
	ip := common.FindStringWithoutMarkers(bodyLower, "hosted at the ip address", "")

	// Extract official URL - try multiple patterns
	// Note: Searches in lowercase body to match Python behavior
	officialURL := common.FindStringWithoutMarkers(bodyLower, "original videos here:", ". ")
	if officialURL == "" {
		officialURL = common.FindStringWithoutMarkers(bodyLower, "paying members only.", "")
	}
	if officialURL == "" {
		officialURL = common.FindStringWithoutMarkers(bodyLower, "at our client's official website here:", "")
	}

	// Create Copyright event type with copyright owner and official URL
	copyrightEvent := &events.Copyright{
		BaseEventType: events.BaseEventType{
			Name: "copyright",
			Type: "copyright",
		},
		CopyrightOwner: copyrightOwner,
		OfficialURL:    officialURL,
	}

	// Extract URLs from the block after "copyright infringement:"
	urls := common.GetBlockAfterWithStop(body, "copyright infringement:", "")

	var eventsResult []*events.Event

	// Create an event for each URL
	for _, url := range urls {
		// Only process lines without spaces (pure URLs)
		if !strings.Contains(strings.TrimSpace(url), " ") {
			event := events.NewEvent("cammodelprotect")
			event.EventTypes = []events.EventType{copyrightEvent}
			event.EventDate = email.ParseDate(dateStr)
			event.IP = ip
			event.URL = url

			eventsResult = append(eventsResult, event)
		}
	}

	return eventsResult, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
