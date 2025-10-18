package manitu

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	event := events.NewEvent("manitu")

	// Check if subject contains DOS or DDOS
	subjectLower := strings.ToLower(subject)
	if strings.Contains(subjectLower, "dos") || strings.Contains(subjectLower, "ddos") {
		return parseDDoS(body, event, serializedEmail)
	}

	// If not a known type, return NewTypeError
	return nil, common.NewNewTypeError(subject)
}

func parseDDoS(body string, event *events.Event, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event.EventTypes = []events.EventType{events.NewDDoS()}

	// Try to extract IP from "abuse from" marker
	if ip := common.GetNonEmptyLineAfter(body, "abuse from"); ip != "" {
		event.IP = ip
	}

	// Determine event date
	if strings.Contains(body, "CURRENTLY RUNNING") {
		// Use the email's date header as fallback
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	} else {
		// Try to find date from specific markers
		labels := []string{"at least from", "starting from (and until now!)"}
		for _, label := range labels {
			if strings.Contains(body, label) {
				dateTimezone := common.GetNonEmptyLineAfter(body, label)
				if dateTimezone != "" {
					// Extract date part (before space)
					dateParts := strings.Fields(dateTimezone)
					if len(dateParts) > 0 {
						dateStr := dateParts[0]
						// Try to parse the date
						if parsedDate := parseDate(dateStr); parsedDate != nil {
							event.EventDate = parsedDate
							break
						}
					}
				}
			}
		}

		// If we still don't have a date, use the email's date header as fallback
		if event.EventDate == nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}
		}
	}

	return []*events.Event{event}, nil
}

// parseDate tries to parse a date string using common formats
func parseDate(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	// Try common date formats
	formats := []string{
		"2006-01-02",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
