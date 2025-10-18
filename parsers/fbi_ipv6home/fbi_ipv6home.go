// Package fbi_ipv6home implements the fbi_ipv6home parser
package fbi_ipv6home

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the fbi_ipv6home parser
type Parser struct{}

// Parse parses emails from @abuse.ipv6home.eu for portscan reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)
	if !strings.Contains(bodyLower, "portscan") {
		return nil, common.NewParserError("email does not contain 'portscan' in body")
	}

	event := events.NewEvent("fbi_ipv6home")
	event.EventTypes = []events.EventType{events.NewPortScan()}
	event.IP = strings.TrimSpace(subject)

	// Extract event date from body between '--' and ';'
	eventDateStr := common.FindStringWithoutMarkers(body, "--", ";")
	if eventDateStr != "" {
		event.EventDate = email.ParseDate(strings.TrimSpace(eventDateStr))
	}

	// Fallback to email date header if event date not found
	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
