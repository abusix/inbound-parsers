package uni_koblenz

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
	// Get body and subject with error checking
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event template
	eventTemplate := events.NewEvent("uni_koblenz")

	// Check subject for event type (case-insensitive)
	subjectLower := strings.ToLower(subject) + ";"

	// Determine event type based on subject keywords
	if strings.Contains(subjectLower, "phishing") || strings.Contains(subjectLower, "phisher") {
		eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
		// If body starts with "http", use first line as URL
		if strings.HasPrefix(body, "http") {
			lines := strings.Split(body, "\n")
			if len(lines) > 0 {
				eventTemplate.URL = strings.TrimSpace(lines[0])
			}
		}
	} else if strings.Contains(subjectLower, "scammer") ||
		strings.Contains(subjectLower, "spammer") ||
		strings.Contains(subjectLower, "virus spreading machines") {
		eventTemplate.EventTypes = []events.EventType{events.NewSpam()}
	} else {
		return nil, common.NewNewTypeError(subjectLower)
	}

	// Extract event date from body or use email header date
	if date := common.FindStringWithoutMarkers(body, "Date: ", ""); date != "" {
		eventTemplate.EventDate = email.ParseDate(date)
	} else {
		if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
			eventTemplate.EventDate = email.ParseDate(dateHeader[0])
		}
	}

	// Extract IP addresses from subject
	ipString := common.FindStringWithoutMarkers(subjectLower, "ips:", ";")

	if ipString == "" {
		// Try alternative format: "IP:" (subject may have space before "ip" that needs handling)
		modifiedSubject := strings.ReplaceAll(subjectLower, " ip ", " ip: ")
		if ip := common.FindStringWithoutMarkers(modifiedSubject, "ip:", ";"); ip != "" {
			eventTemplate.IP = strings.TrimSpace(ip)
			return []*events.Event{eventTemplate}, nil
		}

		// Fallback: extract from body "Received: from ... ]"
		ip := common.FindStringWithoutMarkers(body, "Received: from ", "]")
		eventTemplate.IP = strings.TrimSpace(ip)
		return []*events.Event{eventTemplate}, nil
	}

	// Multiple IPs found - split by comma and create separate events
	ips := strings.Split(ipString, ",")
	var results []*events.Event

	for _, ip := range ips {
		ipTrimmed := strings.TrimSpace(ip)
		if ipTrimmed != "" {
			// Deep copy the event template
			eventCopy := *eventTemplate

			// Copy event types slice
			eventCopy.EventTypes = make([]events.EventType, len(eventTemplate.EventTypes))
			copy(eventCopy.EventTypes, eventTemplate.EventTypes)

			eventCopy.IP = ipTrimmed
			results = append(results, &eventCopy)
		}
	}

	return results, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
