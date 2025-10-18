package cnsd_gob_pe

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
	// Get email body (throws=True in Python)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Create event
	event := events.NewEvent("cnsd_gob_pe")

	// Set event date from email header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract official URL (phishing target)
	officialURL := strings.TrimSpace(common.FindStringWithoutMarkers(
		bodyLower,
		"whose domain is",
		"hosted at the following ip",
	))

	// Create Phishing event type with official URL
	phishing := events.NewPhishing()
	phishing.PhishingTarget = officialURL
	event.EventTypes = []events.EventType{phishing}

	// Extract the phishing domain/URL
	event.URL = common.FindStringWithoutMarkers(bodyLower, "the domain \"", "\" has been")

	// Extract IP address
	ipLine := common.GetNonEmptyLineAfter(bodyLower, "at the following ip address of its platform.")
	event.IP = ipLine

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
