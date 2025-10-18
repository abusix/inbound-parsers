package techspace

import (
	"regexp"
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
	// Get email body (throws=True in Python)
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("techspace")
	event.EventTypes = []events.EventType{events.NewBot("")}

	// Try to extract event date from body using multiple patterns
	var dateStr string

	// Pattern 1: 18/Oct/2024:14:22:45 -0400
	datePattern1 := regexp.MustCompile(`\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} -\d{4}`)
	if match := datePattern1.FindString(body); match != "" {
		dateStr = match
		// Parse: "18/Oct/2024:14:22:45 -0400"
		event.EventDate = parseCustomDate(dateStr, "02/Jan/2006:15:04:05 -0700")
	} else {
		// Pattern 2: Wed Oct 18 14:22:45.123456 2024
		datePattern2 := regexp.MustCompile(`(\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2})\.\d{6}( \d{4})`)
		if matches := datePattern2.FindStringSubmatch(body); len(matches) >= 3 {
			// Combine date + year (matches[1] + matches[2])
			dateStr = matches[1] + matches[2]
			// Parse: "Wed Oct 18 14:22:45 2024"
			event.EventDate = parseCustomDate(dateStr, "Mon Jan 02 15:04:05 2006")
		} else {
			// Pattern 3: 2024-10-18T14:22:45.123456-04:00
			datePattern3 := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2}`)
			if match := datePattern3.FindString(body); match != "" {
				dateStr = match
				// Parse: "2024-10-18T14:22:45.123456-04:00"
				event.EventDate = parseCustomDate(dateStr, "2006-01-02T15:04:05.999999-07:00")
			} else {
				// Fall back to email header date
				if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
					event.EventDate = email.ParseDate(dateHeaders[0])
				}
			}
		}
	}

	// Extract IP address from body: "ip <ip>,"
	ipPattern := regexp.MustCompile(`(?i)ip (\S+),`)
	if matches := ipPattern.FindStringSubmatch(body); len(matches) > 1 {
		event.IP = matches[1]
	}

	return []*events.Event{event}, nil
}

// parseCustomDate parses a date string using the given format
func parseCustomDate(dateStr, format string) *time.Time {
	t, err := time.Parse(format, dateStr)
	if err != nil {
		return nil
	}
	return &t
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
