package dmcapiracyprevention

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
	// Get body - throws error if not available
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get subject - throws error if not available
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract owner from body
	owner := common.FindStringWithoutMarkers(body, "exclusive rights holder for", "")
	owner = strings.Trim(owner, "; ")

	// Extract official URL
	officialURL := common.GetNonEmptyLineAfter(body, "original material is located on the following URL(s):")
	officialURL = strings.TrimSpace(officialURL)

	// Extract external ID from subject (format: "Subject #123")
	externalID := ""
	if parts := strings.Split(subject, "#"); len(parts) > 1 {
		externalID = parts[1]
	}

	// Extract URLs from the block around the marker
	urlLines := common.GetBlockAround(body, "your site at the following URL(s):")

	// Create events for each URL (skip the first line which is the marker)
	var eventsList []*events.Event
	for i := 1; i < len(urlLines); i++ {
		url := strings.TrimSpace(urlLines[i])
		if url == "" {
			continue
		}

		event := events.NewEvent("dmcapiracyprevention")
		event.URL = url

		// Create Copyright event type with owner and official URL
		copyright := events.NewCopyright("", owner, "")
		copyright.OfficialURL = officialURL
		event.EventTypes = []events.EventType{copyright}

		// Set event date from email headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}

		// Add external ID detail if available
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
