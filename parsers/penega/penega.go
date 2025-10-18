package penega

import (
	"fmt"
	"regexp"
	"strings"

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
	bodyLower := strings.ToLower(body)

	// Check for required content
	if !strings.Contains(bodyLower, "network scanning") && !strings.Contains(bodyLower, "network attack") {
		return nil, &common.NewTypeError{Subject: "adapt the parser"}
	}

	// Track unique IP:port combinations
	ipPortSeen := make(map[string]bool)
	var result []*events.Event

	// Find target IP
	targetIP := common.FindStringWithoutMarkers(bodyLower, "destination:", "")

	// Extract log entries
	logLines := common.GetBlockAfterWithStop(bodyLower, "log entries:", "")

	// Regex pattern: [day month date time year] ... [client ip:port]
	// Example: [Mon Jul 13 12:34:56.789012 2020] ... [client 1.2.3.4:56789]
	pattern := regexp.MustCompile(`\[([a-z]*) ([a-z]*) (\d{1,}) ([^\s]*) (\d{1,})\].*\[client ([^\]]*)\]`)

	for _, line := range logLines {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) >= 7 {
			// Extract groups: _, month, day, time, year, ipPort
			month := matches[2]
			day := matches[3]
			timeStr := matches[4]
			year := matches[5]
			ipPort := matches[6]

			// Skip if we've seen this IP:port combination
			if ipPortSeen[ipPort] {
				continue
			}
			ipPortSeen[ipPort] = true

			// Parse IP and port
			parts := strings.Split(ipPort, ":")
			if len(parts) != 2 {
				continue
			}
			ip := parts[0]
			portStr := parts[1]

			// Parse port
			port, err := common.ParsePort(portStr)
			if err != nil {
				continue
			}

			// Parse date (remove milliseconds from time)
			timeParts := strings.Split(timeStr, ".")
			dateStr := fmt.Sprintf("%s %s %s %s", day, month, year, timeParts[0])
			eventDate := email.ParseDate(dateStr)

			// Create event
			event := events.NewEvent("penega")
			event.IP = ip
			event.Port = port
			event.EventDate = eventDate
			event.EventTypes = []events.EventType{events.NewPortScan()}

			// Add target detail
			if targetIP != "" {
				event.AddEventDetail(&events.Target{
					IP: targetIP,
				})
			}

			result = append(result, event)
		}
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
