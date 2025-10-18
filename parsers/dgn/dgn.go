// Package dgn implements the DGN parser
package dgn

import (
	"fmt"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the DGN parser
type Parser struct{}

// NewParser creates a new DGN parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses emails from no-reply@dgn.net.tr
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract IP from subject: IP (xxx.xxx.xxx.xxx)
	ip := common.FindStringWithoutMarkers(subject, "IP (", ")")
	if ip == "" {
		return nil, common.NewParserError("no ip found")
	}

	// Extract timezone from body (format: "UTC +3 unless")
	timeZone := common.FindStringWithoutMarkers(body, "UTC", "unless")

	// Extract date from body
	var dateStr string
	if date := common.FindStringWithoutMarkers(body, "Date of record: ", ""); date != "" {
		// Combine date and timezone (e.g., "2019-11-30 00:07:34" + " +3")
		dateStr = date + timeZone
	} else {
		// Alternative date format: UTC<timezone>: <date>
		utcMarker := "UTC" + strings.TrimSpace(timeZone) + ":"
		dateStr = common.FindStringWithoutMarkers(body, utcMarker, "") + timeZone
	}

	// Create event
	event := events.NewEvent("dgn")
	event.EventTypes = []events.EventType{events.NewDDoS()}
	event.IP = ip

	// Parse the date
	if dateStr != "" {
		event.EventDate = parseDateTime(dateStr)
	}

	return []*events.Event{event}, nil
}

// parseDateTime parses date strings in various formats
// This is similar to Python's magic_datetime_parser
func parseDateTime(dateStr string) *time.Time {
	dateStr = strings.TrimSpace(dateStr)
	if dateStr == "" {
		return nil
	}

	// Normalize timezone format: " +3 " -> " +0300"
	// Handle single or double digit timezone offsets
	dateStr = normalizeTimezone(dateStr)

	// Common date formats used by DGN
	formats := []string{
		// ISO 8601 formats with various timezone notations
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05-0700",
		"2006-01-02 15:04:05 -07:00",
		"2006-01-02 15:04:05 MST",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05 -0700",
		// Date only
		"2006-01-02",
		// Alternative formats
		"02/01/2006 15:04:05 -0700",
		"02-01-2006 15:04:05 -0700",
	}

	// Try parsing with each format
	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// If all parsing fails, return nil
	return nil
}

// normalizeTimezone converts timezone formats like " +3 " or " +03 " to standard " +0300"
func normalizeTimezone(dateStr string) string {
	// Handle " +3 " or " -3 " format (single digit)
	if strings.Contains(dateStr, " +") || strings.Contains(dateStr, " -") {
		// Split by space to isolate timezone
		parts := strings.Fields(dateStr)
		if len(parts) >= 3 {
			// Last part should be the timezone
			lastPart := parts[len(parts)-1]
			if (strings.HasPrefix(lastPart, "+") || strings.HasPrefix(lastPart, "-")) && len(lastPart) <= 3 {
				// Extract the number
				sign := lastPart[0:1]
				numStr := lastPart[1:]

				// Parse the offset hours
				var hours int
				if _, err := fmt.Sscanf(numStr, "%d", &hours); err == nil {
					// Convert to +0300 format (4 digits)
					normalized := fmt.Sprintf("%s%02d00", sign, hours)
					// Replace the last part with normalized timezone
					parts[len(parts)-1] = normalized
					return strings.Join(parts, " ")
				}
			}
		}
	}

	return dateStr
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
