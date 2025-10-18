// Package disney implements the Disney parser for copyright infringement reports
package disney

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Disney parser
type Parser struct{}

// NewParser creates a new Disney parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from @disney.com
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Extract copyrighted work
	copyrightedWork := common.GetNonEmptyLineAfter(bodyLower, "infringed upon:")
	// Split by '(' and take the first part, then trim
	if idx := strings.Index(copyrightedWork, "("); idx != -1 {
		copyrightedWork = copyrightedWork[:idx]
	}
	copyrightedWork = strings.TrimSpace(copyrightedWork)

	// Create event template
	eventTemplate := events.NewEvent("disney")
	eventTemplate.EventTypes = []events.EventType{
		events.NewCopyright(copyrightedWork, "Disney Enterprises, Inc.", ""),
	}

	// Set event date from email headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		eventTemplate.EventDate = eventDate
	}

	// Parse infringing material section
	var urls []string
	var currentIP string
	var result []*events.Event

	startLine := common.GetNonEmptyLineAfter(bodyLower, "location of infringing material:")
	startLine = strings.TrimSpace(startLine)

	lines := strings.Split(bodyLower, "\n")
	var startIndex int = -1

	// Find the start index
	for i, line := range lines {
		if strings.TrimSpace(line) == startLine {
			startIndex = i
			break
		}
	}

	if startIndex == -1 {
		return nil, common.NewParserError("could not find start marker")
	}

	// Process lines from start index onwards
	for i := startIndex; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// Stop at "important notes"
		if strings.Contains(line, "important notes") {
			break
		}

		// Check if line starts with http
		if strings.HasPrefix(line, "http") {
			if currentIP != "" {
				// We have an IP stored, create event immediately
				event := events.NewEvent("disney")
				event.EventTypes = eventTemplate.EventTypes
				event.EventDate = eventTemplate.EventDate
				event.IP = currentIP
				event.URL = line
				result = append(result, event)
			} else {
				// No IP yet, accumulate URL
				urls = append(urls, line)
			}
		} else if ip := common.ExtractOneIP(line); ip != "" {
			// Found an IP on this line
			if len(urls) > 0 {
				// We have URLs waiting, create events for each URL with this IP
				for _, url := range urls {
					event := events.NewEvent("disney")
					event.EventTypes = eventTemplate.EventTypes
					event.EventDate = eventTemplate.EventDate
					event.IP = ip
					event.URL = url
					result = append(result, event)
				}
				// Clear the URLs and IP after processing
				urls = nil
				currentIP = ""
			} else {
				// No URLs waiting, store this IP for next URL
				currentIP = ip
			}
		}
	}

	// If we have URLs left without IPs, create events without IP
	if len(result) == 0 {
		for _, url := range urls {
			event := events.NewEvent("disney")
			event.EventTypes = eventTemplate.EventTypes
			event.EventDate = eventTemplate.EventDate
			event.URL = url
			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
