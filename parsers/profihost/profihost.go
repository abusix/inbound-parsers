package profihost

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
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get email body: %w", err)
	}

	// Extract the attacker's IP
	ip := common.FindStringWithoutMarkers(body, "Host of attacker: ", " =>")
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, fmt.Errorf("could not find attacker IP")
	}

	// Extract timezone for date parsing
	timeZone := extractTimezone(body)
	if timeZone == "" {
		return nil, fmt.Errorf("could not extract timezone")
	}

	// Get log entries
	logLines := common.GetContinuousLinesUntilEmptyLine(body, "Logfile entries")
	if len(logLines) == 0 {
		return nil, fmt.Errorf("no log entries found")
	}

	var result []*events.Event
	var previousDate string

	for _, line := range logLines {
		if !strings.Contains(line, "user:") {
			continue
		}

		// Parse date from line
		date := parseDateFromLine(line, timeZone)
		if date == nil {
			continue
		}

		// Format date as YYYY-MM-DD for comparison
		dateStr := date.Format("2006-01-02")

		// Only create one event per unique date
		if previousDate != dateStr {
			event := events.NewEvent("profihost")
			event.EventDate = date
			event.IP = ip

			// Add LoginAttack event type
			event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

			// Extract target IP
			targetIP := common.FindStringWithoutMarkers(line, "target:", "source:")
			targetIP = strings.TrimSpace(targetIP)
			if targetIP != "" {
				event.AddEventDetail(&events.Target{IP: targetIP})
			}

			result = append(result, event)
			previousDate = dateStr
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no events generated")
	}

	return result, nil
}

// extractTimezone extracts the timezone from the body
// Example: "(time is Europe/Berlin:)" -> "Europe/Berlin"
func extractTimezone(body string) string {
	tz := common.FindStringWithoutMarkers(body, "(time is ", ":")
	tz = strings.ReplaceAll(tz, ")", "")
	tz = strings.ReplaceAll(tz, "(", "")
	tz = strings.TrimSpace(tz)

	// Extract first part before slash if present (e.g., "Europe/Berlin" -> "Europe")
	// This matches the Python behavior: time_zone.split('/')[0]
	if idx := strings.Index(tz, "/"); idx != -1 {
		tz = tz[:idx]
	}

	return tz
}

// parseDateFromLine parses the date from a log line
// Example line: "Oct 31 22:04:04  user: root"
// Combined with timezone to form: "Oct 31 Europe 2024"
func parseDateFromLine(line, timeZone string) *time.Time {
	// Extract date part before "user:"
	datePart := line
	if idx := strings.Index(line, "user:"); idx != -1 {
		datePart = line[:idx]
	}
	datePart = strings.TrimSpace(datePart)
	datePart = strings.Trim(datePart, ": ")

	// Split date into parts: ["Oct", "31", "22:04:04"]
	parts := strings.Fields(datePart)
	if len(parts) < 3 {
		return nil
	}

	// The year is the last element in the original Python logic
	// In the Python version, they do: *main_part, year = date.split()
	// and then reconstruct as: ' '.join([*main_part, time_zone, year])
	// This means: "Oct 31 22:04:04" split -> main_part=["Oct", "31", "22:04:04"], year="" (empty)
	// But actually looking at typical syslog format, it's: "Oct 31 22:04:04"
	// The Python code seems to expect a year at the end, so let's add current year

	// Get current year
	year := fmt.Sprintf("%d", time.Now().Year())

	// Reconstruct date string: "Oct 31 Europe 2024" (matching Python's join)
	// Python does: ' '.join([*main_part, time_zone, year])
	dateStr := strings.Join(parts, " ") + " " + timeZone + " " + year

	// Try to parse the date
	// Format should be like: "Oct 31 22:04:04 Europe 2024"
	// Let's try common syslog formats with timezone
	formats := []string{
		"Jan 2 15:04:05 MST 2006",      // "Oct 31 22:04:04 Europe 2024"
		"Jan 02 15:04:05 MST 2006",     // With zero-padded day
		"Jan _2 15:04:05 MST 2006",     // With space-padded day
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
