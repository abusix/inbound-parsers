package autofusion

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
	// Find text/plain attachment
	textBody, err := common.FindFirstAttachmentWithMimeType(serializedEmail, "text/plain")
	if err != nil {
		// If no text/plain attachment found, return empty
		return nil, nil
	}

	// Check for expected content
	if !strings.Contains(strings.ToLower(textBody), "fake agents") {
		return nil, nil
	}

	lines := strings.Split(textBody, "\n")

	var ip string
	var eventDate string

	// Parse lines to find IP and date
	for _, line := range lines {
		if ip == "" {
			// Extract IP from current line
			ip = common.ExtractOneIP(line)
		} else {
			// Only search for date after IP was found
			// Extract text between markers ' [' and '] '
			dateStr := common.FindStringWithoutMarkers(line, " [", "] ")
			if dateStr != "" {
				// Try to parse the date
				parsedDate := email.ParseDate(dateStr)
				if parsedDate != nil {
					eventDate = dateStr
					break
				}
			}
		}
	}

	// If we found an IP, create an event
	if ip != "" {
		event := events.NewEvent("autofusion")
		event.EventTypes = []events.EventType{events.NewBot("")}
		event.IP = ip

		// Set event date
		if eventDate != "" {
			event.EventDate = email.ParseDate(eventDate)
		} else {
			// Fallback to email header date
			if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
				event.EventDate = email.ParseDate(dateHeader[0])
			}
		}

		return []*events.Event{event}, nil
	}

	return nil, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
