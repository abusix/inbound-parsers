package apiccopyright

import (
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

	// Get date from email header
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}
	if eventDate == nil {
		return nil, nil
	}

	// Parse the email body for event data
	inEventDataSection := false
	var eventDataLines []string

	for _, line := range strings.Split(body, "\n") {
		// Strip leading quote markers and whitespace
		line = strings.TrimLeft(line, "> \t")

		// Don't consider copied HTML emails
		if strings.Contains(line, "<div") || strings.Contains(line, "<br") {
			break
		}

		// Check for section markers
		if strings.HasPrefix(line, "////////////") || strings.Contains(body, "TRADEMARK") {
			inEventDataSection = !inEventDataSection
		}

		if inEventDataSection {
			eventDataLines = append(eventDataLines, line)
		}
	}

	// Extract IP address
	eventDataText := strings.Join(eventDataLines, "\n")
	ipText := common.FindStringWithoutMarkers(strings.ToLower(eventDataText), "ip address", "")
	ip := common.IsIP(common.ExtractOneIP(ipText))

	// Fallback: try to extract IP from TraceRoute section
	if ip == "" {
		traceRouteText := common.FindStringWithoutMarkers(body, "TraceRoute", "[")
		ip = common.ExtractOneIP(traceRouteText)
	}

	// Extract events - find lines with URLs
	var result []*events.Event
	for _, line := range eventDataLines {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "http") || strings.Contains(lineLower, "hxxp") {
			event := events.NewEvent("apiccopyright")
			event.EventDate = eventDate
			event.URL = strings.TrimSpace(line)

			// Set IP if we found one (optional field)
			if ip != "" {
				event.IP = ip
			}

			event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
			result = append(result, event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
