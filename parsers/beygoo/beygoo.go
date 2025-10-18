package beygoo

import (
	"fmt"
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
	bodyLower := strings.ToLower(body)

	// Get event date from headers
	var eventDate string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = dateHeaders[0]
	}

	// Check if it's a trademark complaint
	if strings.Contains(bodyLower, "trademark") {
		event := events.NewEvent("beygoo")
		event.EventDate = email.ParseDate(eventDate)

		// Extract trademark owner
		trademarkOwner := common.FindStringWithoutMarkers(bodyLower, "on behalf of", "concerning")
		trademarkOwner = strings.TrimSpace(trademarkOwner)

		// Extract official URL
		officialURL := common.FindStringWithoutMarkers(bodyLower, "the official website of company is:", "")
		officialURL = strings.ReplaceAll(officialURL, "[.]", ".")

		// Extract the complained URL
		url := common.FindStringWithoutMarkers(bodyLower, "we have noticed that this domain", "was registered")
		url = strings.ReplaceAll(url, "[.]", ".")

		// Create trademark event type
		trademark := events.NewTrademark("", nil, trademarkOwner, "")
		trademark.OfficialURL = officialURL
		event.EventTypes = []events.EventType{trademark}
		event.URL = url

		return []*events.Event{event}, nil
	}

	// If we get here, it's a new type we haven't seen before
	subject, _ := common.GetSubject(serializedEmail, false)
	return nil, fmt.Errorf("new type error: %s", subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
