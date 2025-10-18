package jcloud

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

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var eventsList []*events.Event

	for _, line := range strings.Split(body, "\n") {
		if date := parseMagicDateTime(line); date != nil {
			event := events.NewEvent("jcloud")
			event.EventDate = date
			event.IP = subject
			event.EventTypes = []events.EventType{events.NewDDoS()}

			protocol := strings.TrimSpace(common.FindStringWithoutMarkers(line, "protocol", ","))
			targetPort := strings.TrimSpace(common.FindStringWithoutMarkers(line, "target port", ","))
			sourcePort := strings.TrimSpace(common.FindStringWithoutMarkers(line, "source port", ","))

			if protocol != "" {
				event.AddEventDetail(&events.TransportProtocol{
					Protocol: protocol,
				})
			}

			if targetPort != "" {
				event.AddEventDetail(&events.Target{
					Port: targetPort,
				})
			}

			if sourcePort != "" {
				if port, err := common.ParsePort(sourcePort); err == nil {
					event.Port = port
				}
			}

			eventsList = append(eventsList, event)
		}
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// parseMagicDateTime attempts to parse datetime in various formats
func parseMagicDateTime(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	dateStr = strings.TrimSpace(dateStr)

	// Common formats to try
	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		"Jan 2 2006 15:04:05",
		"Jan 02 2006 15:04:05",
		"2 Jan 2006 15:04:05",
		"02 Jan 2006 15:04:05",
		"Mon Jan 2 15:04:05 2006",
		"Mon Jan 02 15:04:05 2006",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// Try email.ParseDate for RFC 5322 formats
	if t := email.ParseDate(dateStr); t != nil {
		return t
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
