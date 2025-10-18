package interieur_gouv_fr

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Check if this is a child abuse report
	if !strings.Contains(bodyLower, "representations of minors of a pornographic nature") {
		return nil, common.NewNewTypeError("Unknown email type - expected child abuse report")
	}

	// Create event template
	eventTemplate := events.NewEvent("interieur_gouv_fr")
	eventTemplate.EventTypes = []events.EventType{events.NewChildAbuse()}

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Extract IP address
	ipAddress := common.FindStringWithoutMarkers(bodyLower, "is hosted at", "")
	ipAddress = strings.TrimSpace(ipAddress)
	if ipAddress != "" {
		ipAddress = common.ExtractOneIP(ipAddress)
	}

	// Extract URLs block
	urlBlock := common.FindStringWithoutMarkers(
		bodyLower,
		"these contents are visible at the following addresses",
		"technical elements suggest that you are the host of these contents",
	)

	// Parse URLs from the block
	var urls []string
	if urlBlock != "" {
		urlSet := make(map[string]bool)
		lines := strings.Split(urlBlock, "\n")

		for _, line := range lines {
			trimmedLine := strings.TrimSpace(line)

			// Remove trailing markers
			if strings.HasSuffix(trimmedLine, "_**_") {
				trimmedLine = trimmedLine[:len(trimmedLine)-4]
			} else if strings.HasSuffix(trimmedLine, "_*") {
				trimmedLine = trimmedLine[:len(trimmedLine)-2]
			} else if strings.HasSuffix(trimmedLine, "*") {
				trimmedLine = trimmedLine[:len(trimmedLine)-1]
			}

			// Check if line contains a URL
			if strings.Contains(trimmedLine, "http:") || strings.Contains(trimmedLine, "https:") {
				urlSet[trimmedLine] = true
			}
		}

		// Convert set to slice
		for url := range urlSet {
			urls = append(urls, url)
		}
	}

	// Generate events based on what we found
	var results []*events.Event

	if len(urls) == 0 && ipAddress != "" {
		// No URLs found, but we have an IP - create single event
		event := copyEventTemplate(eventTemplate)
		event.IP = ipAddress
		results = append(results, event)
	} else if len(urls) > 0 {
		// Create one event per URL
		for _, url := range urls {
			event := copyEventTemplate(eventTemplate)
			event.URL = url
			if ipAddress != "" {
				event.IP = ipAddress
			}
			results = append(results, event)
		}
	}

	return results, nil
}

// copyEventTemplate creates a deep copy of the event template
func copyEventTemplate(template *events.Event) *events.Event {
	event := events.NewEvent(template.Parser)
	event.EventTypes = template.EventTypes
	event.EventDate = template.EventDate

	// Copy event details
	if len(template.EventDetails) > 0 {
		event.EventDetails = make([]events.EventDetail, len(template.EventDetails))
		copy(event.EventDetails, template.EventDetails)
	}

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
