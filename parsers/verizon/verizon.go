// Package verizon implements the Verizon parser for spamvertised link reports
package verizon

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Verizon parser
type Parser struct{}

// Parse parses Verizon spamvertised link reports
// The parser extracts URLs and IP addresses from reports about spamvertised websites
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, common.NewParserError("failed to get body: " + err.Error())
	}

	// Normalize the body text
	body = strings.ToLower(body)
	body = strings.ReplaceAll(body, "\xa0", "\n")
	body = strings.ReplaceAll(body, "spamvertized", "spamvertised")

	// Check if this is a spamvertised link report
	if !strings.Contains(body, "spamvertised link") {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	// Extract URL and IP pairs
	// Pattern 1: "redirect to:" followed by URL and IP
	pattern1 := regexp.MustCompile(`redirect to:.*\s*(http.*)\s+.*(ip:.*)`)
	matches1 := pattern1.FindAllStringSubmatch(body, -1)

	// Pattern 2: "spamvertised link" followed by URL and IP
	pattern2 := regexp.MustCompile(`spamvertised link.*\s*.*(http.*)\s+.*(ip:.*)`)
	matches2 := pattern2.FindAllStringSubmatch(body, -1)

	// Collect all URL/IP pairs
	var urlIPPairs [][2]string

	// Add matches from pattern 1
	for _, match := range matches1 {
		if len(match) >= 3 {
			urlIPPairs = append(urlIPPairs, [2]string{match[1], match[2]})
		}
	}

	// Add matches from pattern 2
	for _, match := range matches2 {
		if len(match) >= 3 {
			urlIPPairs = append(urlIPPairs, [2]string{match[1], match[2]})
		}
	}

	// Create events from URL/IP pairs
	var eventsList []*events.Event

	for _, pair := range urlIPPairs {
		url := strings.TrimSpace(pair[0])
		ip := strings.TrimSpace(pair[1])

		if url == "" || ip == "" {
			continue
		}

		event := events.NewEvent("verizon")

		// Set event date from email headers
		if serializedEmail.Headers != nil {
			if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
				eventDate := email.ParseDate(dateHeader[0])
				event.EventDate = eventDate
			}
		}

		// Set event type
		event.EventTypes = []events.EventType{events.NewSpamvertised()}

		// Set IP and URL
		event.IP = ip
		event.URL = url

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
