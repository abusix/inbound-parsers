// Package facct implements the facct parser
package facct

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the facct parser
type Parser struct{}

// Parse parses emails from @facct.ru for copyright, trademark, phishing, and fraud reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body with HTML stripped (BeautifulSoup equivalent)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Determine event type based on subject and body content
	bodyLower := strings.ToLower(body)
	subjectLower := strings.ToLower(subject)

	eventTemplate := events.NewEvent("facct")

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Determine event type
	var eventType events.EventType
	if strings.Contains(subjectLower, "copyright") || strings.Contains(bodyLower, "copyright") {
		eventType = events.NewCopyright("", "", "")
	} else if strings.Contains(subjectLower, "trademark") || strings.Contains(bodyLower, "trademark") {
		eventType = events.NewTrademark("", nil, "", "")
	} else if strings.Contains(subjectLower, "phishing") || strings.Contains(bodyLower, "phishing") {
		eventType = events.NewPhishing()
	} else if strings.Contains(subjectLower, "fraud") || strings.Contains(bodyLower, "fraud") {
		eventType = events.NewFraud()
	} else {
		return nil, common.NewParserError("unknown event type in subject: " + subject)
	}
	eventTemplate.EventTypes = []events.EventType{eventType}

	// Extract IP
	ipStr := common.FindStringWithoutMarkers(body, "IP", ")")
	eventTemplate.IP = strings.TrimSpace(ipStr)

	var result []*events.Event

	// Try to extract URLs from the first pattern: "the following link" to "FACCT is an"
	urlString := common.FindStringWithoutMarkers(body, "the following link", "FACCT is an")
	if urlString != "" {
		// Split by "http" and reassemble URLs
		urls := strings.Split(urlString, "http")
		for _, urlPart := range urls {
			if urlPart == "" {
				continue
			}
			url := "http" + urlPart
			url = strings.TrimSpace(url)

			// Create a copy of the event
			event := copyEvent(eventTemplate)
			event.URL = url
			result = append(result, event)
		}
	} else {
		// Try alternative URL extraction pattern
		urlBlock := common.FindStringWithoutMarkers(body, "the URL for your reference:", "In case you are a hosting provider")
		if urlBlock != "" {
			urlBlock = strings.TrimSpace(urlBlock)
			lines := strings.Split(urlBlock, "\n")
			if len(lines) > 0 {
				eventTemplate.URL = strings.TrimSpace(lines[len(lines)-1])
			}
			result = append(result, eventTemplate)
		} else if eventTemplate.IP != "" {
			// If we have an IP but no URL, still return the event
			result = append(result, eventTemplate)
		}
	}

	return result, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent("facct")
	event.EventDate = template.EventDate
	event.IP = template.IP
	event.EventTypes = make([]events.EventType, len(template.EventTypes))
	copy(event.EventTypes, template.EventTypes)
	// Copy event details if any
	for _, detail := range template.EventDetails {
		event.EventDetails = append(event.EventDetails, detail)
	}
	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
