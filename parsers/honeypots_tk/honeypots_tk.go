// Package honeypots_tk implements the honeypots.tk parser
package honeypots_tk

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the honeypots.tk parser
type Parser struct{}

// Parse parses emails from honeypots.tk
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	return parseLoginAttack(subject, body, serializedEmail)
}

func parseLoginAttack(subject, body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	eventTemplate := events.NewEvent("honeypots_tk")
	eventTemplate.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Set IP from subject
	eventTemplate.IP = subject

	// Try to extract event date from body
	bodyLower := strings.ToLower(body)
	dateStr := common.FindStringWithoutMarkers(bodyLower, "date ranges :", "to")
	dateStr = strings.TrimSpace(dateStr)

	if dateStr != "" {
		if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
			eventTemplate.EventDate = parsedDate
		}
	}

	// Fallback to email date header if event date not found
	if eventTemplate.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract protocol
	protocol := common.FindStringWithoutMarkers(bodyLower, "protocol-s :", "")
	protocol = strings.TrimSpace(protocol)

	// Extract target IPs
	targetIPsStr := common.FindStringWithoutMarkers(bodyLower, "effected server-s :", "")
	targetIPsStr = strings.TrimSpace(targetIPsStr)

	var allTargetIPs []string
	if targetIPsStr != "" {
		// Split on comma
		for _, ip := range strings.Split(targetIPsStr, ",") {
			trimmed := strings.TrimSpace(ip)
			if trimmed != "" {
				allTargetIPs = append(allTargetIPs, trimmed)
			}
		}
	}

	// Create one event per target IP
	var result []*events.Event
	for _, targetIP := range allTargetIPs {
		// Deep copy the event template
		event := events.NewEvent("honeypots_tk")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		event.IP = eventTemplate.IP
		event.EventDate = eventTemplate.EventDate

		// Add target detail
		event.AddEventDetail(&events.Target{
			Service: protocol,
			IP:      targetIP,
		})

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
