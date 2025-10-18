package dd_tech

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	// Check if subject contains "spam"
	if !strings.Contains(subjectLower, "spam") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	event := events.NewEvent("dd_tech")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract received line and IP
	receivedLine := common.FindStringWithoutMarkers(body, "Received:", "")
	ip := common.FindStringWithoutMarkers(body, "CIP:", "")

	// If no CIP found, use received line
	if ip == "" {
		ip = receivedLine
	}

	// Validate and set IP
	if validIP := common.ExtractOneIP(ip); validIP != "" {
		event.IP = validIP
	}

	// Try to parse event date from received line
	if receivedLine != "" {
		parts := strings.Split(receivedLine, ";")
		if len(parts) > 0 {
			dateStr := strings.TrimSpace(parts[len(parts)-1])
			if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Fallback to email header date if parsing failed
	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
