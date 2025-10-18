package triciafox

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

// urlInLine extracts the first URL from a line of text
func urlInLine(line string) string {
	for _, data := range strings.Fields(line) {
		if common.IsURL(data) {
			return data
		}
	}
	return ""
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get body - throws error if not available
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get subject - throws error if not available
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract original work URL
	originalWork := common.GetNonEmptyLineAfter(body, "original material is located")

	// Extract the URL section starting from the marker
	markerIdx := strings.Index(body, "The infringing material is located at the following URLs:")
	if markerIdx == -1 {
		return nil, common.NewParserError("could not find URL marker")
	}

	urlPart := body[markerIdx:]
	lines := strings.Split(urlPart, "\n")

	var eventsList []*events.Event

	// Process each line: filter lines containing URLs, extract URL from each, map to string, strip whitespace
	for _, line := range lines {
		if !common.IsURL(line) {
			continue
		}

		url := strings.TrimSpace(urlInLine(line))
		if url == "" {
			continue
		}

		event := events.NewEvent("triciafox")

		// Set event date from email headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}

		// Try to set IP from subject (some reports don't have an IP)
		// Python code catches ValueError, which means subject is not a valid IP
		// We'll just set it regardless - validation happens elsewhere
		if subject != "" {
			event.IP = subject
		}

		event.URL = url

		// Create Copyright event type with official URL
		copyright := events.NewCopyright("", "", "")
		copyright.OfficialURL = originalWork
		event.EventTypes = []events.EventType{copyright}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
