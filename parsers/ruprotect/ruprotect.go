// Package ruprotect implements the ruprotect.com parser
package ruprotect

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ruprotect parser
type Parser struct{}

var (
	// Pattern to match entries like "- example.com (192.0.2.1)"
	entryPattern = regexp.MustCompile(`- (\S+) \((\S+)\)`)
	// Pattern to match URLs containing the domain
	urlPattern = regexp.MustCompile(`http\S+`)
)

// Parse parses emails from @ruprotect.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Extract the copyright owner
	owner := common.FindStringWithoutMarkers(body, "The  ", "is the owner")
	owner = strings.TrimSpace(owner)

	// Get event date from header
	var eventDate *time.Time
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract the IP block between the markers
	ipBlock := common.FindStringWithoutMarkers(
		body,
		"sites listed below.",
		"We request that you immediately do the following:",
	)

	// Find all entries matching the pattern
	matches := entryPattern.FindAllStringSubmatch(ipBlock, -1)
	if len(matches) == 0 {
		return nil, common.NewParserError("No entries found in ruprotect parser")
	}

	var result []*events.Event

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		event := events.NewEvent("ruprotect")

		// Set copyright information
		copyright := events.NewCopyright("", owner, "")
		event.EventTypes = []events.EventType{copyright}

		// Set event date
		event.EventDate = eventDate

		urlDomain := match[1]
		ip := match[2]

		// Set IP
		event.IP = ip

		// Try to find a full URL containing the domain
		urlPattern := regexp.MustCompile(`http\S+` + regexp.QuoteMeta(urlDomain) + `\S+`)
		if urlMatch := urlPattern.FindString(body); urlMatch != "" {
			event.URL = urlMatch
		} else {
			event.URL = urlDomain
		}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
