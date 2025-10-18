// Package ilvasapolli implements the ilvasapolli parser
package ilvasapolli

import (
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the ilvasapolli parser
type Parser struct{}

// Parse parses emails from ilvasapolli
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = strings.ToLower(body)

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subject = strings.ToLower(subject)

	// Check if subject contains "connection attempts"
	if !strings.Contains(subject, "connection attempts") {
		return nil, common.NewNewTypeError(subject)
	}

	// Parse IP (from)
	ip := common.FindStringWithoutMarkers(body, "ip (from)", "")
	ip = strings.Trim(ip, " :")

	// Parse destination IP
	dstIP := common.FindStringWithoutMarkers(body, "destination ip", "")
	dstIP = strings.Trim(dstIP, " :")

	// Parse destination port
	dstPort := common.FindStringWithoutMarkers(body, "port", "")
	dstPort = strings.Trim(dstPort, " :")

	// Parse date
	eventDate, err := parseDate(body)
	if err != nil {
		return nil, err
	}

	// Create event
	event := events.NewEvent("ilvasapolli")
	event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	event.EventDate = eventDate
	event.IP = ip

	// Add target as event detail
	event.AddEventDetail(&events.Target{
		IP:   dstIP,
		Port: dstPort,
	})

	return []*events.Event{event}, nil
}

// parseDate parses the date from the email body
// Expected format: "date and time: 2024-01-15.12:30:45 UTC"
// Returns parsed time.Time
func parseDate(body string) (*time.Time, error) {
	dateStr := common.FindStringWithoutMarkers(body, "date and time", "")
	dateStr = strings.Trim(dateStr, " :")

	// Check that date contains UTC
	if !strings.Contains(body, "utc") {
		return nil, common.NewParserError("date format changed adapt the parser")
	}

	// Parse the date string
	// Expected format: "2024-01-15.12:30:45" or similar
	// Try common formats
	formats := []string{
		"2006-01-02.15:04:05",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, strings.TrimSpace(dateStr)); err == nil {
			return &t, nil
		}
	}

	return nil, common.NewParserError("failed to parse date: " + dateStr)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
