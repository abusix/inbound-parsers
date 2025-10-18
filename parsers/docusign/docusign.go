package docusign

import (
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

	// Create event
	event := events.NewEvent("docusign")

	// Parse event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract URL from body
	urlStr := common.FindStringWithoutMarkers(body, "URL:", "")
	event.URL = common.CleanURL(urlStr)

	// Extract IP from body
	ipStr := common.FindStringWithoutMarkers(body, "IP:", "")
	event.IP = common.ExtractOneIP(ipStr)

	// Create phishing event type with the URL
	phishing := events.NewPhishing()
	phishing.PhishingTarget = event.URL

	// Create trademark event type for DocuSign
	trademark := events.NewTrademark("", nil, "DocuSign", "")

	// Set event types
	event.EventTypes = []events.EventType{phishing, trademark}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
