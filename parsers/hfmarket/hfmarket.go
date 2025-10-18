// Package hfmarket implements the HFMarket parser for malicious activity reports
package hfmarket

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the HFMarket parser
type Parser struct{}

var ipPattern = regexp.MustCompile(`(\[?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\[?\.\]?\d{0,3}\]?)`)

// Parse parses emails from hfmarket
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subject, _ := common.GetSubject(serializedEmail, false)

	bodyLower := strings.ToLower(body)

	// Check if this is a recognized report type
	if !strings.Contains(bodyLower, "abuse emails received") &&
	   !strings.Contains(bodyLower, "attacking our websites") {
		return nil, common.NewNewTypeError(subject)
	}

	// Parse malicious activity
	return parseMaliciousActivity(bodyLower, serializedEmail)
}

func parseMaliciousActivity(bodyLower string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("hfmarket")

	// Try to extract event date from body
	eventDateStr := common.FindStringWithoutMarkers(bodyLower, "between <b>", "</b>")
	if eventDateStr != "" {
		eventDate := email.ParseDate(eventDateStr)
		event.EventDate = eventDate
	} else {
		// Fall back to email date header
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}
	}

	// Set event type
	event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	// Extract IP address
	ipMatch := ipPattern.FindStringSubmatch(bodyLower)
	if len(ipMatch) > 1 {
		ipStr := ipMatch[1]
		// Clean up IP by removing brackets and [.] obfuscation
		ipStr = strings.ReplaceAll(ipStr, "[.]", ".")
		ipStr = strings.ReplaceAll(ipStr, "[", "")
		ipStr = strings.ReplaceAll(ipStr, "]", "")
		ipStr = strings.TrimSpace(ipStr)

		// Validate and set IP
		if validIP := common.IsIP(ipStr); validIP != "" {
			event.IP = validIP
			return []*events.Event{event}, nil
		}
	}

	// No valid IP found
	return nil, common.NewParserError("no valid IP address found in email body")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
