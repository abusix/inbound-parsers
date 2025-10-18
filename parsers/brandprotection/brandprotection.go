package brandprotection

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

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event template with common fields
	eventTemplate := events.NewEvent("brandprotection")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract external ID from subject: ECIN:xxx]
	externalID := common.FindStringWithoutMarkers(subject, "ECIN:", "]")
	if externalID != "" {
		eventTemplate.AddEventDetail(&events.ExternalID{ID: externalID})
	}

	// Extract trademark information
	country := strings.TrimSpace(common.FindStringWithoutMarkers(
		body, "are registered worldwide and include", "Registration",
	))

	regNumber := strings.TrimSpace(common.FindStringWithoutMarkers(
		body, "Registration No.", "for the",
	))
	var regNumbers []string
	if regNumber != "" {
		regNumbers = []string{regNumber}
	}

	trademark := strings.TrimSpace(common.FindStringWithoutMarkers(
		body, "for the", "mark",
	))

	owner := strings.TrimSpace(common.FindStringWithoutMarkers(
		body, "Madam", "owns some of the most",
	))

	// Set event type to Trademark
	eventTemplate.EventTypes = []events.EventType{
		events.NewTrademark(country, regNumbers, owner, trademark),
	}

	// Normalize body for URL extraction
	body = strings.ReplaceAll(body,
		"Following URLs infringes the rights of the Company:",
		"Following URLs infringes the rights of the Company:\n",
	)

	// Extract URLs
	var urls []string
	if strings.Contains(body, "Following URLs infringes the rights of the Company:") {
		urls = common.GetBlockAfterWithStop(body, "Following URLs infringes the rights of the Company:", "")
	} else {
		urls = common.GetBlockAfterWithStop(body, "Please see the following URL(s) below:", "")
	}

	// Create one event per URL
	var result []*events.Event
	for _, url := range urls {
		// Deep copy the event template
		event := &events.Event{}
		*event = *eventTemplate

		// Copy EventTypes slice
		event.EventTypes = make([]events.EventType, len(eventTemplate.EventTypes))
		copy(event.EventTypes, eventTemplate.EventTypes)

		// Copy EventDetails slice
		event.EventDetails = make([]events.EventDetail, len(eventTemplate.EventDetails))
		copy(event.EventDetails, eventTemplate.EventDetails)

		// Set URL
		event.URL = strings.TrimSpace(url)

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no URLs found in email body")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
