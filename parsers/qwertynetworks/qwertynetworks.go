package qwertynetworks

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getTextLinebreak determines the linebreak style used in the text
func getTextLinebreak(text string) string {
	if strings.Contains(text, "\r\n") {
		return "\r\n"
	}
	return "\n"
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

	// Extract case number from subject
	caseID := common.FindStringWithoutMarkers(subject, "#", " ")

	// Extract data section from body
	dataPart := common.FindStringWithoutMarkers(body, "Abuse log:", "Please take action")
	dataPart = strings.TrimSpace(dataPart)

	// Determine line break style
	newline := getTextLinebreak(body)

	var result []*events.Event

	// Split by double newlines to get individual abuse records
	records := strings.Split(dataPart, newline+newline)

	for _, data := range records {
		lines := strings.Split(strings.TrimSpace(data), "\n")
		if len(lines) >= 2 {
			event := events.NewEvent("qwertynetworks")

			// Parse first line: contains timestamp and IP
			// Example: "2024-01-01 12:00:00 (UTC+1) IP 1.2.3.4:"
			firstLine := lines[0]

			// Extract timezone from parentheses
			tz := common.FindStringWithoutMarkers(firstLine, "(", ")")
			if len(tz) > 3 {
				tz = tz[3:] // Remove "UTC" prefix
			}

			// Fix single-digit timezone offset (e.g., "+1" -> "+01")
			if len(tz) == 2 {
				tz = string(tz[0]) + "0" + string(tz[1])
			}

			// Extract date/time (first 19 characters) and combine with timezone
			dateStr := firstLine[:19] + " " + tz
			event.EventDate = email.ParseDate(dateStr)

			// Extract IP address
			event.IP = common.FindStringWithoutMarkers(firstLine, "IP", ":")

			// Parse second line: contains URL and port
			// Example: "URL http://example.com port 80;"
			if len(lines) > 1 {
				secondLine := lines[1]

				targetURL := common.FindStringWithoutMarkers(secondLine, "URL ", " ")
				targetPort := common.FindStringWithoutMarkers(secondLine, "port ", ";")

				// Add Target event detail
				target := &events.Target{
					Port: targetPort,
					URL:  targetURL,
				}
				event.AddEventDetail(target)
			}

			// Add external case ID
			if caseID != "" {
				event.AddEventDetail(&events.ExternalID{ID: caseID})
			}

			// Set event type to LoginAttack
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

			result = append(result, event)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no abuse records found in email")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
