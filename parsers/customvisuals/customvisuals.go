package customvisuals

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
	body, _ := common.GetBody(serializedEmail, true)
	subject, _ := common.GetSubject(serializedEmail, true)

	// Replace <br> with newlines (matching Python: body.replace('<br>', '\n'))
	body = strings.ReplaceAll(body, "<br>", "\n")

	event := events.NewEvent("customvisuals")

	// Extract IP from subject
	// Python: find_string_without_markers(subject + '$', 'IP ', '$').strip()
	event.IP = strings.TrimSpace(common.FindStringWithoutMarkers(subject+"$", "IP ", "$"))

	// Get the log line after "The log line for"
	dataLine := common.GetNonEmptyLineAfter(body, "The log line for")

	// Extract port from data_line
	// Python: find_string_without_markers(data_line, 'port ', ' ')
	if portStr := common.FindStringWithoutMarkers(dataLine, "port ", " "); portStr != "" {
		if port, err := common.ParsePort(portStr); err == nil {
			event.Port = port
		}
	}

	// Extract target IP
	// Python: find_string_without_markers(body, 'Our server at ', ' ')
	targetIP := common.FindStringWithoutMarkers(body, "Our server at ", " ")

	// Extract date from first two words of data_line
	// Python: date = ' '.join(data_line.split()[:2])
	words := strings.Fields(dataLine)
	var date string
	if len(words) >= 2 {
		date = words[0] + " " + words[1]
	}

	// Set event date
	event.EventDate = email.ParseDate(date)

	// Set event type to login_attack
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Add target as event detail
	if targetIP != "" {
		event.AddEventDetail(&events.Target{
			IP: targetIP,
		})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
