// Package hosteurope implements the HostEurope parser for phishing and webhack reports
package hosteurope

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the HostEurope parser
type Parser struct{}

var urlPattern = regexp.MustCompile(`(?i)(uri|url):\s*https?://\w+`)

// Parse parses emails from hosteurope.de
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Check for webhack reports
	if strings.Contains(subjectLower, "exploit") && strings.Contains(bodyLower, "bruteforce attacks") {
		return parseWebHack(subject, body)
	}

	// Check for phishing reports
	if strings.Contains(bodyLower, "phishing") {
		return parsePhishing(body, serializedEmail)
	}

	// Unknown email type
	return nil, common.NewNewTypeError(serializedEmail.Identifier)
}

// parseWebHack parses webhack reports
func parseWebHack(subject, body string) ([]*events.Event, error) {
	marker := "\n---"
	startIndex := strings.Index(body, marker)
	if startIndex == -1 {
		return nil, common.NewParserError("marker not found in body")
	}

	startIndex += len(marker)
	endIndex := strings.Index(body[startIndex:], marker)
	if endIndex == -1 {
		return nil, common.NewParserError("end marker not found in body")
	}

	// Extract the section between markers
	section := strings.TrimSpace(body[startIndex : startIndex+endIndex])

	// Create event template
	eventTemplate := events.NewEvent("hosteurope")

	// Try to parse IP from subject
	if ip := common.IsIP(subject); ip != "" {
		eventTemplate.IP = ip
	}

	var eventsList []*events.Event

	// Process each line in the section
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue // Skip malformed lines
		}

		// Create a copy of the template
		event := events.NewEvent("hosteurope")
		if eventTemplate.IP != "" {
			event.IP = eventTemplate.IP
		}

		// Parse event date from fields[3], fields[4], fields[5]
		// Format: date time timezone
		if len(fields) >= 6 {
			eventDateStr := fields[3] + " " + fields[4] + " " + fields[5]
			eventDate := email.ParseDate(eventDateStr)
			event.EventDate = eventDate
		}

		// Only create event if we have both event_date and IP
		if event.EventDate != nil && event.IP != "" {
			event.EventTypes = []events.EventType{events.NewWebHack()}

			// Add target IP (last field)
			targetIP := fields[len(fields)-1]
			if validTargetIP := common.IsIP(targetIP); validTargetIP != "" {
				event.AddEventDetail(&events.Target{
					IP: validTargetIP,
				})
			}

			eventsList = append(eventsList, event)
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created from webhack report")
	}

	return eventsList, nil
}

// parsePhishing parses phishing reports
func parsePhishing(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	infringingURLs := getInfringingURLs(body)
	if len(infringingURLs) == 0 {
		return nil, common.NewParserError("no URLs found in phishing report")
	}

	// Get date from headers
	var dateStr string
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateStr = dateHeaders[0]
		}
	}

	var eventsList []*events.Event

	for _, url := range infringingURLs {
		event := events.NewEvent("hosteurope")

		// Parse and set event date
		if dateStr != "" {
			eventDate := email.ParseDate(dateStr)
			event.EventDate = eventDate
		}

		// Set event type
		event.EventTypes = []events.EventType{events.NewPhishing()}

		// Set URL
		event.URL = url

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// getInfringingURLs extracts URLs from the email body
func getInfringingURLs(body string) []string {
	var infringingURLs []string
	var urlsMatch []string

	// Find all URL matches
	for _, line := range strings.Split(body, "\n") {
		matches := urlPattern.FindAllString(line, -1)
		urlsMatch = append(urlsMatch, matches...)
	}

	// Extract URLs from matches
	for _, match := range urlsMatch {
		// Split on colon and take everything after the first colon
		parts := strings.SplitN(match, ":", 2)
		if len(parts) >= 2 {
			url := strings.TrimSpace(parts[1])
			infringingURLs = append(infringingURLs, url)
		}
	}

	return infringingURLs
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
