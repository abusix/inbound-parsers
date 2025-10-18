package flyhosting

import (
	"regexp"
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

	// Convert to lowercase for case-insensitive matching
	bodyLower := strings.ToLower(body)

	event := events.NewEvent("flyhosting")

	// Determine event type based on content
	if strings.Contains(bodyLower, "port scan") {
		event.EventTypes = []events.EventType{events.NewPortScan()}
	} else if strings.Contains(bodyLower, "bruteforce") {
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	}

	// Try to extract date from body using regex
	// Format: "Wed Mar 11 12:34:56 2020" (weekday month day time year)
	datePattern := regexp.MustCompile(`(?i)(\w{3} \w{3} \d+ \d{2}:\d{2}:\d{2} \d{4})`)
	if matches := datePattern.FindStringSubmatch(body); len(matches) > 1 {
		dateStr := matches[1]
		parsedDate := parseCustomDate(dateStr)
		if parsedDate != nil {
			event.EventDate = parsedDate
		}
	} else {
		// Fall back to email header date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract IP address from body
	// Looking for text between "detected from host" and "#"
	ip := common.FindStringWithoutMarkers(bodyLower, "detected from host", "#")
	if ip != "" {
		// Validate and set IP
		if validIP := common.ExtractOneIP(ip); validIP != "" {
			event.IP = validIP
		}
	}

	return []*events.Event{event}, nil
}

// parseCustomDate parses date strings in the format "Wed Mar 11 12:34:56 2020"
func parseCustomDate(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	// Try various formats similar to what's in the Python code
	formats := []string{
		"Mon Jan 2 15:04:05 2006",   // Single digit day
		"Mon Jan 02 15:04:05 2006",  // Double digit day
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
