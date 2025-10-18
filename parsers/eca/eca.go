// Package eca implements the eca parser
package eca

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the eca parser
type Parser struct{}

// Parse parses emails for eca web hack reports from Ukrainian authorities
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	ip := common.FindStringWithoutMarkers(bodyLower, "ip:", "")
	ip = strings.TrimSpace(ip)

	event := events.NewEvent("eca")
	event.IP = ip
	event.EventTypes = []events.EventType{events.NewWebHack()}

	// Parse event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
