package barrettlawgroup

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

	// Check if subject contains 'fw:'
	if !strings.Contains(subjectLower, "fw:") {
		return nil, common.NewNewTypeError(subjectLower)
	}

	event := events.NewEvent("barrettlawgroup")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Find "Received: from" header and extract the full header
	received := strings.TrimSpace(common.FindString(body, "Received: from", "\n"))

	// Get continuous lines until empty line (for multi-line received headers)
	afterReceived := common.GetContinuousLinesUntilEmptyLine(body, received)

	// Concatenate lines that start with whitespace (continuation lines)
	for _, line := range afterReceived {
		if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
			received = received + " " + strings.TrimSpace(line)
		} else {
			break
		}
	}

	// Extract IP from received header (between [ and ])
	ip := common.FindStringWithoutMarkers(received, "[", "]")
	if ip != "" {
		event.IP = ip
	}

	// Extract event date from received header (after last ';')
	parts := strings.Split(received, ";")
	if len(parts) > 0 {
		eventDate := strings.TrimSpace(parts[len(parts)-1])
		if eventDate != "" {
			event.EventDate = email.ParseDate(eventDate)
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
