package dgt

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// IP_PATTERN matches the unusual IP format used in DGT emails: \d{3}.\d{3}.\d{3}.\d{2}
// This appears to be a malformed IP pattern - likely meant to match standard IPs
var ipPattern = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return []*events.Event{}, nil
	}

	event := events.NewEvent("dgt")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Parse body line by line
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		// Look for IP address pattern
		if ipPattern.MatchString(line) {
			// Find &nbsp marker to extract IP
			index := strings.Index(line, "&nbsp")
			if index != -1 {
				ipCandidate := line[:index]
				// Validate the IP
				ip := common.IsIP(ipCandidate)
				if ip != "" {
					event.IP = ip
				}
			}
		}

		// Look for http:// URLs (excluding specific domains)
		if strings.Contains(line, "http://") &&
			!strings.Contains(line, "http://legalaccess") &&
			!strings.Contains(line, "http://dgt") {

			startIndex := strings.Index(line, "http://")
			remaining := line[startIndex:]
			endIndex := strings.Index(remaining, "<")

			if endIndex != -1 {
				account := remaining[:endIndex]
				event.AddEventDetailSimple("source_account", account)
			}
		}
	}

	// Extract copyright owner
	owner := common.FindStringWithoutMarkers(
		body,
		"used to provide access to",
		"contents protected by copyright",
	)
	owner = strings.TrimSpace(owner)

	// Set event type with copyright information
	event.EventTypes = []events.EventType{events.NewCopyright("", owner, "")}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
