// Package prsformusic implements the PRS for Music parser for copyright infringement reports
package prsformusic

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the PRS for Music parser
type Parser struct{}

// Parse parses emails from @prsformusic.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject (both required)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subject = strings.ToLower(subject)

	// Extract external ID from subject
	externalID := common.FindStringWithoutMarkers(subject, "our ref:", ")")

	// Extract copyrighted work - get the first non-empty line after the marker
	copyrightWorkLines := common.GetBlockAfterWithStop(body, "following copyright work", "")
	if len(copyrightWorkLines) == 0 {
		return nil, common.NewParserError("could not find copyright work")
	}
	copyrightWork := copyrightWorkLines[0]

	// Extract URLs - get all non-empty lines after the marker
	urls := common.GetBlockAfterWithStop(body, "following url", "")

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Create one event per URL
	var eventsList []*events.Event

	for _, url := range urls {
		event := events.NewEvent("prsformusic")
		event.URL = url
		event.EventTypes = []events.EventType{events.NewCopyright(copyrightWork, "", "")}
		event.EventDate = eventDate

		// Add external ID if found
		if externalID != "" {
			event.AddEventDetail(&events.ExternalID{ID: externalID})
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
