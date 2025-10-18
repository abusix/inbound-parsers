package defaria

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
	// Get email body and subject
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Check if this is a "break into" email
	if !strings.Contains(subject, "break into") {
		return nil, common.NewNewTypeError(subject)
	}

	// Create event
	event := events.NewEvent("defaria")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

	// Try to extract event date from body
	eventDateStr := common.FindStringWithoutMarkers(body, "attempted access on", "<")
	if eventDateStr != "" {
		// Parse date format: "Jan 02 15:04:05" (missing year)
		// Python uses: datetime.strptime(event_date.strip(), '%b %d %X')
		// %b = abbreviated month name, %d = day, %X = time (HH:MM:SS)
		eventDateStr = strings.TrimSpace(eventDateStr)

		// Add current year since the format doesn't include it
		currentYear := time.Now().Year()
		dateWithYear := fmt.Sprintf("%s %d", eventDateStr, currentYear)

		// Try parsing with year appended
		parsedTime, err := time.Parse("Jan 2 15:04:05 2006", dateWithYear)
		if err == nil {
			event.EventDate = &parsedTime
		}
	}

	// Fallback to email date header if event date not found
	if event.EventDate == nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			parsedDate := email.ParseDate(dateHeaders[0])
			if parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Extract IP address from body
	ipAddr := common.FindStringWithoutMarkers(body, "IP Address of", "has been")
	ipAddr = strings.TrimSpace(ipAddr)
	if ipAddr != "" {
		event.IP = ipAddr
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
