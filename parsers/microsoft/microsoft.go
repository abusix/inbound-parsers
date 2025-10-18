package microsoft

import (
	"fmt"
	"strings"
	"time"

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

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	event := events.NewEvent("microsoft")

	// Extract IP from subject
	event.IP = subjectLower

	// Extract URL from body
	url := common.FindStringWithoutMarkers(bodyLower, "url: ", "")
	if url != "" {
		event.URL = url
	}

	// Only proceed if we have IP or URL
	if event.IP == "" && url == "" {
		return nil, common.NewParserError("no IP or URL found")
	}

	// Extract event date from body
	eventDateStr := common.FindStringWithoutMarkers(bodyLower, "last seen: ", "")
	if eventDateStr != "" {
		// Parse date in format: "Oct 18, 2025 14:30 UTC"
		// Python format: '%b %d, %Y %H:%M %Z'
		eventDate := parseEventDate(eventDateStr)
		if eventDate != nil {
			event.EventDate = eventDate
		}
	}

	// Extract destination port from body
	destinationPort := common.FindStringWithoutMarkers(bodyLower, "port: ", "")
	if destinationPort != "" {
		port, err := common.ParsePort(destinationPort)
		if err == nil {
			event.Port = port
		}
	}

	// Check for Cobalt Strike malware
	if strings.Contains(bodyLower, "cobalt strike") {
		event.EventTypes = []events.EventType{events.NewMalware("Cobalt Strike")}
		return []*events.Event{event}, nil
	}

	// If not Cobalt Strike, return error for new type
	return nil, fmt.Errorf("new malware type detected in subject: %s", subject)
}

// parseEventDate parses date string in format: "Oct 18, 2025 14:30 UTC"
// Matching Python's: datetime.strptime(event_date, '%b %d, %Y %H:%M %Z')
func parseEventDate(dateStr string) *time.Time {
	dateStr = strings.TrimSpace(dateStr)
	if dateStr == "" {
		return nil
	}

	// Convert Python strftime format to Go time format
	// Python: '%b %d, %Y %H:%M %Z'
	// Go: 'Jan 2, 2006 15:04 MST'
	format := "Jan 2, 2006 15:04 MST"

	if t, err := time.Parse(format, dateStr); err == nil {
		return &t
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
