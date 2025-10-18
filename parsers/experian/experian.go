// Package experian implements the experian parser
package experian

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the experian parser
type Parser struct{}

// Parse parses emails from @experian.com for malicious activity reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	bodyLower := strings.ToLower(body)

	_, err = common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	eventTemplate := events.NewEvent("experian")
	eventTemplate.EventTypes = []events.EventType{events.NewMaliciousActivity()}

	timeStr := strings.TrimSpace(common.FindStringWithoutMarkers(bodyLower, "time:", ""))
	eventTemplate.EventDate = email.ParseDate(timeStr)
	if eventTemplate.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Normalize body
	bodyLower = strings.ReplaceAll(bodyLower, "src ip", "src")
	bodyLower = strings.ReplaceAll(bodyLower, "source ip address/port", "src")
	bodyLower = strings.ReplaceAll(bodyLower, "source ip", "src")
	bodyLower = strings.ReplaceAll(bodyLower, "destination ip address/port", "dest")
	bodyLower = strings.ReplaceAll(bodyLower, " :", ":")

	// Try to extract destination
	dstIP := common.FindStringWithoutMarkers(bodyLower, "dest:", "")
	if dstIP != "" {
		target := &events.Target{IP: dstIP}
		eventTemplate.AddEventDetail(target)
	}

	var result []*events.Event

	// Try single IP extraction
	if ip := common.FindStringWithoutMarkers(bodyLower, "src:", ""); ip != "" {
		eventTemplate.IP = ip
		result = append(result, eventTemplate)
	} else if ip := common.FindStringWithoutMarkers(bodyLower, "from the ip address", ""); ip != "" {
		eventTemplate.IP = ip
		result = append(result, eventTemplate)
	} else {
		// Extract IP block
		ipBlock := common.GetContinuousLinesUntilEmptyLine(bodyLower, "src:")
		seen := make(map[string]bool)
		for _, ip := range ipBlock {
			if !seen[ip] {
				seen[ip] = true
				event := copyEvent(eventTemplate)
				event.IP = ip
				result = append(result, event)
			}
		}
	}

	return result, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent("experian")
	event.EventDate = template.EventDate
	event.EventTypes = make([]events.EventType, len(template.EventTypes))
	copy(event.EventTypes, template.EventTypes)
	// Copy event details
	for _, detail := range template.EventDetails {
		event.EventDetails = append(event.EventDetails, detail)
	}
	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
