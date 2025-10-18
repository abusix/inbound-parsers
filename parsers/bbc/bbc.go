package bbc

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	// Create event template
	eventTemplate := events.NewEvent("bbc")

	// Determine event type based on body content
	if strings.Contains(bodyLower, "ddos") {
		eventTemplate.EventTypes = []events.EventType{events.NewDDoS()}
	} else {
		// If not DDoS, it's an unknown type - return error
		return nil, &common.NewTypeError{Subject: subject}
	}

	// Try to extract event date from body
	eventDate := common.FindStringWithoutMarkers(bodyLower, "between \"", "\" and")
	if eventDate != "" {
		eventTemplate.EventDate = email.ParseDate(eventDate)
	} else {
		// Fall back to email header date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	var result []*events.Event

	// Check if body contains "client_ip" - multiple IP extraction mode
	if strings.Contains(bodyLower, "client_ip") {
		// Split at "client_ip" and extract all IPs from the block after it
		parts := strings.Split(bodyLower, "client_ip")
		if len(parts) > 1 {
			eventBlock := parts[1]
			ips := make(map[string]bool) // Track unique IPs
			lines := strings.Split(eventBlock, "\n")

			for _, line := range lines {
				line = strings.TrimSpace(line)
				ip := common.IsIP(line)
				if ip != "" && !ips[ip] {
					ips[ip] = true
					// Create a new event for each unique IP
					event := events.NewEvent("bbc")
					event.EventTypes = eventTemplate.EventTypes
					event.EventDate = eventTemplate.EventDate
					event.IP = ip
					result = append(result, event)
				}
			}
		}
	} else {
		// Single IP mode - extract from "abuse report for the following ip address"
		eventTemplate.IP = common.GetNonEmptyLineAfter(bodyLower, "abuse report for the following ip address")
		result = append(result, eventTemplate)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
