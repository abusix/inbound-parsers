// Package tampabay implements the Tampa Bay (lindroth@tampabay.rr.com) parser
package tampabay

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

var (
	// datePattern matches dates like "Mon, 02 Mar 2004 12:34:56 +0400"
	datePattern = regexp.MustCompile(`(?P<date>\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} \+\d{4})`)

	// urlPattern matches URLs in subject like "url (something)"
	urlPattern = regexp.MustCompile(`(?P<url>\S+)\s+\(\S+\)`)
)

func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from lindroth@tampabay.rr.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get subject and body
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event template
	eventTemplate := events.NewEvent("tampabay")

	// Check if it's spam based on subject
	if !strings.Contains(strings.ToLower(subject), "spam") {
		return nil, common.NewNewTypeError(subject)
	}

	// Set event type to spam
	eventTemplate.EventTypes = []events.EventType{events.NewSpam()}

	// Extract event date from body if available
	if match := datePattern.FindStringSubmatch(body); len(match) > 1 {
		eventDate := email.ParseDate(match[1])
		if eventDate != nil {
			eventTemplate.EventDate = eventDate
		}
	}

	// Extract URLs from subject
	var urls []string
	matches := urlPattern.FindAllStringSubmatch(subject, -1)
	for _, match := range matches {
		if len(match) > 1 {
			urls = append(urls, match[1])
		}
	}

	var eventsList []*events.Event

	// Create events for each URL found in subject
	if len(urls) > 0 {
		for _, url := range urls {
			// Create a deep copy of the event template
			event := events.NewEvent("tampabay")
			event.EventTypes = eventTemplate.EventTypes
			event.EventDate = eventTemplate.EventDate
			event.URL = url
			eventsList = append(eventsList, event)
		}
	} else {
		// Try to use subject as URL
		if common.IsURL(subject) {
			eventTemplate.URL = subject
			eventsList = append(eventsList, eventTemplate)
		} else {
			// Look for URLs starting with "http" in body lines
			lines := strings.Split(body, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "http") {
					event := events.NewEvent("tampabay")
					event.EventTypes = eventTemplate.EventTypes
					event.EventDate = eventTemplate.EventDate
					event.URL = line
					eventsList = append(eventsList, event)
				}
			}
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no URLs found in subject or body")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
