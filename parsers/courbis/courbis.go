package courbis

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var datePattern = regexp.MustCompile(`(?i)date : (?P<timestamp>\d{2,4}\-\d{2}\-\d{2,4} \d{2}:\d{2}:\d{2}) `)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Reject if body is empty (matches Python's match() logic)
	if strings.TrimSpace(strings.ToLower(body)) == "" {
		return nil, common.NewNewTypeError("empty body")
	}

	// Check if subject contains "spam"
	if !strings.Contains(strings.ToLower(subject), "spam") {
		return nil, common.NewNewTypeError(subject)
	}

	// Get date fallback from headers
	var dateFallback *time.Time
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			dateFallback = email.ParseDate(dateHeaders[0])
		}
	}

	return parseSpam(body, subject, dateFallback)
}

func parseSpam(body, subject string, dateFallback *time.Time) ([]*events.Event, error) {
	event := events.NewEvent("courbis")
	event.EventDate = dateFallback
	event.EventTypes = []events.EventType{events.NewSpam()}
	event.IP = subject

	// Try to extract date from body
	if match := datePattern.FindStringSubmatch(body); match != nil {
		// Extract the named group "timestamp"
		for i, name := range datePattern.SubexpNames() {
			if name == "timestamp" && i < len(match) {
				// Parse the date string from body
				if parsedDate := email.ParseDate(match[i]); parsedDate != nil {
					event.EventDate = parsedDate
				}
				break
			}
		}
	}

	// Only yield event if it has IP or URL
	if event.IP != "" || event.URL != "" {
		return []*events.Event{event}, nil
	}

	return []*events.Event{}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
