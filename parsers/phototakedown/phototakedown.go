package phototakedown

import (
	"strings"
	"time"

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

	subject, _ := common.GetSubject(serializedEmail, false)

	// Get event date from email header
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Check if body contains "copyright" keyword
	if !strings.Contains(body, "copyright") {
		return nil, common.NewNewTypeError(subject)
	}

	// Create event
	event := events.NewEvent("phototakedown")
	event.EventDate = eventDate
	event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}

	// Extract external ID (Reference)
	externalID := common.FindStringWithoutMarkers(body, "Reference:", "</p")
	externalID = strings.TrimSpace(externalID)
	if externalID != "" {
		event.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Extract URL
	url := common.FindStringWithoutMarkers(body, "infringing copy is located at:", "<br")
	event.URL = strings.TrimSpace(url)

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
