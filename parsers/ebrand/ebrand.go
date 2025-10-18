// Package ebrand implements the ebrand parser
package ebrand

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ebrand parser
type Parser struct{}

// Parse parses emails for ebrand trademark and phishing reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	eventTemplate := events.NewEvent("ebrand")

	// Parse event date
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventTemplate.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Determine event type
	if strings.Contains(body, "trademark") ||
		strings.Contains(body, "intellectual property infringement") ||
		strings.Contains(body, "intellectual property rights") {
		eventTemplate.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
	} else if strings.Contains(subjectLower, "phishing") {
		eventTemplate.EventTypes = []events.EventType{events.NewPhishing()}
	} else {
		return nil, common.NewNewTypeError(subject)
	}

	// Extract URLs using multiple patterns
	var urls []string

	if strings.Contains(body, "certain domain registered through your services,") {
		url := common.FindStringWithoutMarkers(body, "certain domain registered through your services,", " is")
		if url != "" {
			urls = append(urls, strings.TrimSpace(url))
		}
	} else if strings.Contains(body, "The list of URLs:") {
		urls = common.GetContinuousLinesUntilEmptyLine(body, "The list of URLs:")
	} else if strings.Contains(body, "Example of infringing url's:") {
		lines := common.GetContinuousLinesUntilEmptyLine(body, "Example of infringing url's:")
		for _, line := range lines {
			if common.IsURL(line) {
				urls = append(urls, line)
			}
		}
	} else if strings.Contains(body, "Infringing webstore:") {
		urls = common.GetContinuousLinesUntilEmptyLine(body, "Infringing webstore:")
	} else if strings.Contains(body, "Infringing url:") {
		urls = common.GetContinuousLinesUntilEmptyLine(body, "Infringing url:")
	} else {
		// Try regex pattern to find URLs
		urlRe := regexp.MustCompile(`http\S+`)
		if match := urlRe.FindString(body); match != "" {
			urls = append(urls, match)
		} else {
			// Fallback to subject
			urls = append(urls, subjectLower)
		}
	}

	// Create events
	var result []*events.Event
	for _, url := range urls {
		event := copyEvent(eventTemplate)
		event.URL = url
		result = append(result, event)
	}

	return result, nil
}

// copyEvent creates a deep copy of an event
func copyEvent(template *events.Event) *events.Event {
	event := events.NewEvent("ebrand")
	event.EventDate = template.EventDate
	event.EventTypes = make([]events.EventType, len(template.EventTypes))
	copy(event.EventTypes, template.EventTypes)
	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
