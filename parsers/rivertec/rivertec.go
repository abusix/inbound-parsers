// Package rivertec implements the Rivertec parser for junk mail reports
package rivertec

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Rivertec parser
type Parser struct{}

// Parse parses emails from @rivertec addresses
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Check if it's a junk mail report
	if !strings.Contains(bodyLower, "junk mail") {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	// Extract source and target IPs using regex
	// Pattern: subscriber [ip1/ip2/...] ... advertiser [ip1/ip2/...]
	pattern := regexp.MustCompile(`subscriber\s+\[(.*?)\].*advertiser\s+\[(.*?)\]`)
	matches := pattern.FindStringSubmatch(bodyLower)

	var srcIPs, targetIPs []string
	if len(matches) >= 3 {
		// Split IPs by '/'
		if matches[1] != "" {
			srcIPs = strings.Split(matches[1], "/")
		}
		if matches[2] != "" {
			targetIPs = strings.Split(matches[2], "/")
		}
	}

	// Extract date
	dateStr := common.FindStringWithoutMarkers(bodyLower, "date: ", "")

	// Parse date
	var eventDate *time.Time
	if dateStr != "" {
		eventDate = email.ParseDate(dateStr)
	}

	// Create events for each source IP
	var eventsList []*events.Event

	for _, ipStr := range srcIPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		// Validate IP
		validIP := common.IsIP(ipStr)
		if validIP == "" {
			continue
		}

		event := events.NewEvent("rivertec")

		// Set event type to spam
		event.EventTypes = []events.EventType{events.NewSpam()}

		// Set event date
		event.EventDate = eventDate

		// Set IP
		event.IP = validIP

		// Add target IP as event detail if available
		if len(targetIPs) > 0 && targetIPs[0] != "" {
			targetIP := strings.TrimSpace(targetIPs[0])
			if validTargetIP := common.IsIP(targetIP); validTargetIP != "" {
				event.AddEventDetail(&events.Target{
					IP: validTargetIP,
				})
			}
		}

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
