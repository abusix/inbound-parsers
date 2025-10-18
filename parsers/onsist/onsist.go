// Package onsist implements the Onsist parser for copyright infringement reports
package onsist

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Onsist parser
type Parser struct{}

// NewParser creates a new Onsist parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from @onsist.net
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("onsist")

	// Extract URL after "copyright infringement:"
	event.URL = common.GetNonEmptyLineAfter(body, "copyright infringement:")

	// Extract IP address after "IP address "
	event.IP = common.FindStringWithoutMarkers(body, "IP address ", "")

	// Set event date from email headers
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract copyright owner
	copyrightOwner := common.FindStringWithoutMarkers(body, "Onsist represents", "(")
	copyrightOwner = strings.TrimSpace(copyrightOwner)

	// Set event type (work and protocol are empty in Python version)
	event.EventTypes = []events.EventType{events.NewCopyright("", copyrightOwner, "")}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
