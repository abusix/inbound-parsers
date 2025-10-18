package avoxi

import (
	"fmt"
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

	bodyLower := strings.ToLower(body)

	// Check if this is a brute force attack email
	if !strings.Contains(bodyLower, "bruteforce") {
		return nil, common.NewNewTypeError("adapt the parser")
	}

	// Extract IP and date using regex
	// Pattern: "ip address (.*) generated at ([^\n]*)\n"
	re := regexp.MustCompile(`ip address (.*?) generated at ([^\n]+)`)
	matches := re.FindStringSubmatch(bodyLower)
	if len(matches) < 3 {
		return nil, common.NewParserError("regex did not match adapt the parser")
	}

	ip := strings.TrimSpace(matches[1])
	dateString := strings.TrimSpace(matches[2])

	// Clean up date string
	dateString = strings.ReplaceAll(dateString, "  ", " ")

	// Parse date string: expected format like "fri jan  8 08:06:51 est 2021"
	// Split: [day_name, month, day, time, zone, year]
	parts := strings.Fields(dateString)
	if len(parts) < 6 {
		return nil, common.NewParserError("invalid date format")
	}

	// Get month, day, time, zone, year (skip day name at index 0)
	month := parts[1]
	day := parts[2]
	timeStr := parts[3]
	zone := strings.ToLower(parts[4])
	year := parts[5]

	// Validate timezone
	if zone != "edt" && zone != "est" {
		return nil, common.NewParserError("invalid timezone")
	}

	// Pad day with zero if needed
	if len(day) == 1 {
		day = "0" + day
	}

	// Capitalize month and zone to match Go time format
	// Convert first letter to uppercase for month name
	if len(month) > 0 {
		month = strings.ToUpper(month[:1]) + strings.ToLower(month[1:])
	}
	zoneUpper := strings.ToUpper(zone)

	// Format: "2 Jan 2006 15:04:05 MST" is close to what ParseDate supports
	// But we have "2021 Jan 08 08:06:51 EST" which needs custom parsing
	// Build the date string in a format that time.Parse can handle
	formattedDate := fmt.Sprintf("%s %s %s %s", day, month, year, timeStr)

	// Parse using custom format
	parsedTime, err := parseAvoxiDate(formattedDate, zoneUpper)
	if err != nil {
		return nil, common.NewParserError(fmt.Sprintf("failed to parse date: %v", err))
	}

	// Create event
	event := events.NewEvent("avoxi")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	event.IP = ip
	event.EventDate = parsedTime

	return []*events.Event{event}, nil
}

// parseAvoxiDate parses a date in the format "08 Jan 2021 08:06:51" with timezone
func parseAvoxiDate(dateStr, timezone string) (*time.Time, error) {
	// Format: "2 Jan 2006 15:04:05 MST"
	// Our input: "08 Jan 2021 08:06:51" + timezone
	fullDateStr := fmt.Sprintf("%s %s", dateStr, timezone)

	// Try parsing with the format
	layout := "02 Jan 2006 15:04:05 MST"
	t, err := time.Parse(layout, fullDateStr)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
