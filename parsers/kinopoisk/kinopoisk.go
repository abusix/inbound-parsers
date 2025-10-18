package kinopoisk

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	event := events.NewEvent("kinopoisk")

	// Extract external ID from subject [id]
	externalID := common.FindString(subject, "[", "]")
	if externalID != "" {
		// Remove the brackets to get just the ID
		externalID = strings.TrimPrefix(externalID, "[")
		externalID = strings.TrimSuffix(externalID, "]")
		event.AddEventDetail(&events.ExternalID{
			ID: externalID,
		})
	}

	// Set event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		event.EventDate = eventDate
	}

	// Check if this is a copyright complaint
	if strings.Contains(body, "copyright") {
		event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

		// Extract URL from body
		url := common.FindStringWithoutMarkers(body, "containing the Content:", "I have a good")
		if url != "" {
			event.URL = url
		}

		return []*events.Event{event}, nil
	}

	// Unknown type
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
