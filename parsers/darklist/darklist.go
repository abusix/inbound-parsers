package darklist

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
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Extract IP from subject line (format: "... : <IP>$")
	ip := common.FindStringWithoutMarkers(subject+"$", ": ", "$")

	// Extract timezone from body
	tzLine := common.FindStringWithoutMarkers(body, "timezone is", ")")
	tzLine = strings.TrimSpace(tzLine)
	tz := ""
	if len(tzLine) > 3 {
		tz = tzLine[3:]
	}

	// Parse event date
	var eventDate *time.Time

	// Try to extract date from timespan line
	dateLine := common.FindStringWithoutMarkers(body, "timespan: ", " - ")
	dateLine = strings.TrimSpace(dateLine)

	if dateLine != "" {
		// Replace dots with slashes and append timezone
		dateLine = strings.ReplaceAll(dateLine, ".", "/") + " " + tz
		eventDate = parseMagicDateTime(dateLine)
	} else if strings.Contains(body, "Date:") {
		// Try to find "Date:" line
		dateLine = common.FindStringWithoutMarkers(body, "Date:", "")
		eventDate = parseMagicDateTime(dateLine)
	} else {
		// Extract year from email date header
		var year int
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			headerDate := email.ParseDate(dateHeaders[0])
			if headerDate != nil {
				year = headerDate.Year()
			}
		}

		// Try to get date from "Log excerpt:" line
		logLine := common.GetNonEmptyLineAfter(body, "Log excerpt:")
		if logLine != "" {
			parts := strings.Fields(logLine)
			if len(parts) >= 3 {
				// Format: "DD MMM HH:MM:SS"
				// Reconstruct as "MMM DD YYYY HH:MM:SS TZ"
				dateStr := fmt.Sprintf("%s %s %d %s %s", parts[1], parts[0], year, parts[2], tz)
				eventDate = parseMagicDateTime(dateStr)
			}
		}

		// Fallback to email date header
		if eventDate == nil {
			if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
				eventDate = email.ParseDate(dateHeaders[0])
			}
		}
	}

	// Extract target IP
	targetIPLine := common.FindStringWithoutMarkers(body, "against one of our", "")
	targetIP := common.ExtractOneIP(targetIPLine)

	// Extract ports from "Log excerpt:" block
	ports := make(map[string]bool)
	logBlock := common.GetBlockAround(body, "Log excerpt:")
	for _, line := range logBlock {
		portStr := common.FindStringWithoutMarkers(line, " port ", " ")
		if portStr != "" {
			// Split by colon and take first part
			parts := strings.Split(portStr, ":")
			if len(parts) > 0 && parts[0] != "" {
				ports[parts[0]] = true
			}
		}
	}

	// Create events
	var eventList []*events.Event

	if len(ports) > 0 {
		// Create one event per port
		for portStr := range ports {
			port, err := common.ParsePort(portStr)
			if err != nil {
				continue
			}

			event := events.NewEvent("darklist")
			event.IP = ip
			event.EventDate = eventDate
			event.Port = port

			if targetIP != "" {
				event.AddEventDetail(&events.Target{IP: targetIP})
			}

			event.EventTypes = []events.EventType{
				events.NewLoginAttack("", ""),
				events.NewBlacklist(""),
			}

			eventList = append(eventList, event)
		}
	} else {
		// Create single event without port
		event := events.NewEvent("darklist")
		event.IP = ip
		event.EventDate = eventDate

		if targetIP != "" {
			event.AddEventDetail(&events.Target{IP: targetIP})
		}

		event.EventTypes = []events.EventType{
			events.NewLoginAttack("", ""),
			events.NewBlacklist(""),
		}

		eventList = append(eventList, event)
	}

	return eventList, nil
}

// parseMagicDateTime attempts to parse datetime in various formats
func parseMagicDateTime(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	dateStr = strings.TrimSpace(dateStr)

	// Common formats to try
	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		"Jan 2 2006 15:04:05",
		"Jan 02 2006 15:04:05",
		"2 Jan 2006 15:04:05",
		"02 Jan 2006 15:04:05",
		"Mon Jan 2 15:04:05 2006",
		"Mon Jan 02 15:04:05 2006",
		"2006-01-02",
		"01/02/2006 15:04:05 MST",
		"1/2/2006 15:04:05 MST",
		"Jan 2 2006 15:04:05 MST",
		"Jan 02 2006 15:04:05 MST",
		"2 Jan 2006 15:04:05 MST",
		"02 Jan 2006 15:04:05 MST",
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
