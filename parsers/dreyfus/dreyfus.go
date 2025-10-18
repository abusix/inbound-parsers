// Package dreyfus implements the dreyfus.fr parser
package dreyfus

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the dreyfus parser
type Parser struct{}

// NewParser creates a new dreyfus parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from contact@dreyfus.fr
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("dreyfus")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Determine event type based on body content
	if strings.Contains(body, "trademark") {
		event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if strings.Contains(body, "promoting illegal activities") {
		event.EventTypes = []events.EventType{events.NewIllegalAdvertisement()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Extract IP address from body
	ip := common.FindStringWithoutMarkers(body, "IP address", "that appear")
	if ip != "" {
		event.IP = strings.TrimSpace(ip)
	}

	// Extract URL from body or subject
	url := common.FindStringWithoutMarkers(body, "domain name", ">")
	if url != "" {
		event.URL = strings.TrimSpace(url)
	} else {
		// Try to extract from subject
		url = common.FindStringWithoutMarkers(strings.ToLower(subject), "domain name <", ">")
		if url != "" {
			event.URL = strings.TrimSpace(url)
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
