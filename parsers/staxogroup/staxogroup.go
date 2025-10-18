package staxogroup

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

// parseWordfenceDate parses date strings in the format used by Wordfence
// Example: "Monday 1st January 2024 01:30:45 PM"
// The Python version uses arrow.get(date, 'dddd Do MMMM YYYY hh:mm:ss A')
func parseWordfenceDate(dateStr string) *time.Time {
	// Remove ordinal suffixes (1st, 2nd, 3rd, 4th, etc.)
	re := regexp.MustCompile(`(\d+)(st|nd|rd|th)`)
	dateStr = re.ReplaceAllString(dateStr, "$1")

	// Try parsing with various formats
	formats := []string{
		"Monday 2 January 2006 03:04:05 PM",  // 12-hour with day name
		"Monday 2 January 2006 15:04:05",     // 24-hour with day name
		"2 January 2006 03:04:05 PM",         // 12-hour without day name
		"2 January 2006 15:04:05",            // 24-hour without day name
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			// Convert to UTC
			utc := t.UTC()
			return &utc
		}
	}

	// If parsing fails, return nil (will store as string in Python version)
	return nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Normalize subject - remove newlines and carriage returns
	subject = strings.ReplaceAll(subject, "\n", "")
	subject = strings.ReplaceAll(subject, "\r", "")
	subjectLower := strings.ToLower(subject)

	// Check if subject contains "user locked out"
	if !strings.Contains(subjectLower, "user locked out") {
		return nil, common.NewNewTypeError(subject)
	}

	event := events.NewEvent("staxogroup")

	// Extract date between "by the Wordfence plugin at" and "The Wordfence"
	dateStr := common.FindStringWithoutMarkers(body, "by the Wordfence plugin at", "The Wordfence")
	dateStr = strings.TrimSpace(dateStr)

	// Clean up the date string - remove "of " and "at "
	dateStr = strings.ReplaceAll(dateStr, "of ", "")
	dateStr = strings.ReplaceAll(dateStr, "at ", "")

	// Parse the date
	parsedDate := parseWordfenceDate(dateStr)
	if parsedDate != nil {
		event.EventDate = parsedDate
	}
	// Note: Python version falls back to storing the string if parsing fails
	// In Go, we just leave EventDate as nil if parsing fails

	// Extract IP address - find text between "User IP:" and "User"
	ipStr := common.FindStringWithoutMarkers(body, "User IP:", "User")
	event.IP = strings.TrimSpace(ipStr)

	// Extract username - find text between "last username they tried to sign in with was: '" and "'"
	username := common.FindStringWithoutMarkers(body, "last username they tried to sign in with was: '", "'")

	// Create LoginAttack event type with username
	event.EventTypes = []events.EventType{events.NewLoginAttack(username, "")}

	// Extract URL from subject - find text between ']' and 'user'
	url := common.FindStringWithoutMarkers(subject, "]", "user")
	url = strings.TrimSpace(url)

	// Add Target event detail with the URL
	if url != "" {
		event.AddEventDetail(&events.Target{URL: url})
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
