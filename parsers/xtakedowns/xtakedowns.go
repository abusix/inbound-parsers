// Package xtakedowns implements the xtakedowns parser
// This is a 100% exact Go translation of Python's xtakedowns.py
package xtakedowns

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Match returns true if the email is from @xtakedowns
func Match(serializedEmail *email.SerializedEmail, fromAddr string) bool {
	if fromAddr == "" || !strings.Contains(fromAddr, "@xtakedowns") {
		return false
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return false
	}

	if strings.HasPrefix(strings.ToLower(subject), "re:") {
		return false
	}

	return true
}

// Parse processes the xtakedowns abuse email
func Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Normalize body: lowercase and replace double spaces with single space
	bodyLower := strings.ToLower(body)
	bodyLower = strings.ReplaceAll(bodyLower, "  ", " ")

	// Extract owner from "on behalf of" to "in this matter"
	owner := common.FindStringWithoutMarkers(bodyLower, "on behalf of", "in this matter")
	owner = strings.ReplaceAll(owner, "\r\n", " ")
	owner = strings.TrimSpace(owner)

	// Extract official URL from line after "brands:"
	officialURL := common.GetNonEmptyLineAfter(bodyLower, "brands:")

	// Extract external ID from "copyright infringement notice [" to "]"
	extID := common.FindStringWithoutMarkers(bodyLower, "copyright infringement notice [", "]")

	// Extract IP address
	ip := common.FindStringWithoutMarkers(bodyLower, "ip address:", "")

	// Get event date from headers
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract URLs from block after "copyright infringement notice"
	urls := common.GetBlockAfter(bodyLower, "copyright infringement notice")

	var result []*events.Event

	for _, url := range urls {
		event := events.NewEvent("xtakedowns")
		event.IP = ip
		event.URL = url
		event.EventDate = eventDate

		// Add external ID
		if extID != "" {
			event.AddEventDetail(&events.ExternalID{
				ID: extID,
			})
		}

		// Create Copyright event type
		copyright := &events.Copyright{
			BaseEventType: events.BaseEventType{
				Name: "copyright",
				Type: "copyright",
			},
			OfficialURL:    officialURL,
			CopyrightOwner: owner,
		}
		event.EventTypes = []events.EventType{copyright}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
