package sony

import (
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	email "github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// loginAttackReasons are the reasons that indicate a login attack
var loginAttackReasons = []string{"Account Takeover", "Fraudulent Account"}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract CSV data after the marker
	csvLines := common.GetBlockAfterWithStop(body, "The following table of IP addresses, dates and times", "")
	if csvLines == nil || len(csvLines) == 0 {
		return nil, common.NewParserError("Data marker not found")
	}

	// Join lines back into a CSV string
	csvData := strings.Join(csvLines, "\n")

	// Parse CSV with unix dialect (skipinitialspace=True in Python)
	reader := csv.NewReader(strings.NewReader(csvData))
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, common.NewParserError(fmt.Sprintf("failed to parse CSV: %v", err))
	}

	if len(records) == 0 {
		return nil, common.NewParserError("empty CSV data")
	}

	// First row is headers
	headers := records[0]

	// Create header index map
	headerMap := make(map[string]int)
	for i, header := range headers {
		headerMap[strings.TrimSpace(header)] = i
	}

	var eventsList []*events.Event

	// Process each data row
	for i := 1; i < len(records); i++ {
		row := records[i]
		if len(row) != len(headers) {
			continue // Skip malformed rows
		}

		// Create entry map
		entry := make(map[string]string)
		for j, header := range headers {
			entry[strings.TrimSpace(header)] = strings.TrimSpace(row[j])
		}

		event := events.NewEvent("sony")

		// Get date range and parse event date
		dateRange := entry["Approximate Time Range (UTC)"]
		event.AddEventDetailSimple("date_range", dateRange)

		// Parse the date using a flexible parser
		eventDate := parseDateRange(dateRange)
		event.EventDate = eventDate

		// Set IP address
		event.IP = entry["IP Address"]

		// Determine event type based on reason
		reason := entry["Reason"]
		isLoginAttack := false
		for _, attackReason := range loginAttackReasons {
			if strings.Contains(reason, attackReason) {
				isLoginAttack = true
				break
			}
		}

		if isLoginAttack {
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
		} else {
			// Unknown reason - return an error in the event
			event.Error = fmt.Sprintf("Unknown reason: %s", reason)
			event.EventTypes = []events.EventType{events.NewUnknown()}
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events parsed from CSV")
	}

	return eventsList, nil
}

// parseDateRange parses various date formats that might appear in the date range field
// This is similar to magic_datetime_parser in Python
func parseDateRange(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	// Trim whitespace
	dateStr = strings.TrimSpace(dateStr)

	// Try various date formats that might appear
	formats := []string{
		// ISO 8601 formats
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",

		// US formats
		"01/02/2006 15:04:05",
		"01/02/2006 3:04:05 PM",
		"01/02/2006",
		"1/2/2006 15:04:05",
		"1/2/2006 3:04:05 PM",
		"1/2/2006",

		// European formats
		"02/01/2006 15:04:05",
		"02/01/2006",
		"2/1/2006 15:04:05",
		"2/1/2006",

		// Other common formats
		"Jan 02, 2006 15:04:05",
		"Jan 02, 2006",
		"January 02, 2006",
		"02-Jan-2006 15:04:05",
		"02-Jan-2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// If all parsing fails, return nil
	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
