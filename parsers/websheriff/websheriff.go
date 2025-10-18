// Package websheriff implements the websheriff.com parser
package websheriff

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the websheriff parser
type Parser struct{}

// Parse parses emails from @websheriff.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Replace " :" with ":" to normalize formatting
	body = strings.ReplaceAll(body, " :", ":")

	// Extract copyright owner from "1. Rights Owner" field
	ownerLine := common.FindStringWithoutMarkers(body, "1. Rights Owner", "")
	if ownerLine == "" {
		return nil, common.NewParserError("Could not find '1. Rights Owner' in websheriff email")
	}

	// Parse: "1. Rights Owner: Owner Name (details)"
	// Split by ":" and get the part after it
	parts := strings.Split(ownerLine, ":")
	if len(parts) < 2 {
		return nil, common.NewParserError("Could not parse owner from '1. Rights Owner' line")
	}

	// Get the owner name before any parenthesis
	ownerPart := parts[1]
	owner := strings.Split(ownerPart, "(")[0]
	owner = strings.TrimSpace(owner)

	// Get the first URL after "Location(s):"
	firstURL := common.GetNonEmptyLineAfter(body, "Location(s):")
	if firstURL == "" {
		return nil, common.NewParserError("Could not find any URL after 'Location(s):' in websheriff email")
	}

	// Get event date from email headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract all URLs from the block around the first URL
	block := common.GetBlockAround(body, firstURL)
	var eventList []*events.Event

	for _, line := range block {
		if strings.HasPrefix(line, "http") {
			event := events.NewEvent("websheriff")
			event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}
			event.URL = line
			event.EventDate = eventDate
			eventList = append(eventList, event)
		}
	}

	if len(eventList) == 0 {
		return nil, common.NewParserError("No URLs found in websheriff email")
	}

	return eventList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
