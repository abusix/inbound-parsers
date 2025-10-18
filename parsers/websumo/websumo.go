// Package websumo implements the WebSumo parser for malicious activity reports
package websumo

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the WebSumo parser
type Parser struct{}

// Parse parses emails from info@websumo.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body and subject
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Check for known email type
	if strings.Contains(bodyLower, "hacker is using one or maybe more of your systems") {
		event := events.NewEvent("websumo")

		// Set event type
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		// Extract attacker IP (source)
		attackerIP := common.FindStringWithoutMarkers(bodyLower, "the origin of the attacker is", "")
		attackerIP = strings.TrimSpace(attackerIP)
		if validIP := common.IsIP(attackerIP); validIP != "" {
			event.IP = validIP
		}

		// Extract destination IP (target)
		dstIP := common.FindStringWithoutMarkers(bodyLower, "destination is", "")
		dstIP = strings.TrimSpace(dstIP)
		if validIP := common.IsIP(dstIP); validIP != "" {
			event.AddEventDetail(&events.Target{
				IP: validIP,
			})
		}

		// Extract event date from body (between brackets)
		eventDate := common.FindStringWithoutMarkers(bodyLower, "[", "]")
		eventDate = strings.TrimSpace(eventDate)
		if eventDate != "" {
			parsedDate := email.ParseDate(eventDate)
			if parsedDate != nil {
				event.EventDate = parsedDate
			} else {
				// Fall back to email date header
				if date, ok := serializedEmail.Headers["date"]; ok && len(date) > 0 {
					parsedDate = email.ParseDate(date[0])
					event.EventDate = parsedDate
				}
			}
		} else {
			// No date in brackets, use email date header
			if date, ok := serializedEmail.Headers["date"]; ok && len(date) > 0 {
				parsedDate := email.ParseDate(date[0])
				event.EventDate = parsedDate
			}
		}

		return []*events.Event{event}, nil
	}

	// Unknown email type
	return nil, common.NewNewTypeError(subject)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
