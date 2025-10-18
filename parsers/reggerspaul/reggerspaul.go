// Package reggerspaul implements the reggerspaul.be parser
package reggerspaul

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the reggerspaul parser
type Parser struct{}

// Parse parses emails from @reggerspaul.be
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get the log extract block
	lx := common.GetBlockAround(body, "Logextract:")
	if len(lx) <= 1 {
		return nil, fmt.Errorf("no log extract found")
	}

	// Skip the first line (header with "Logextract:")
	lx = lx[1:]

	// Check if this is a PORTSCAN event
	if !strings.Contains(body, "PORTSCAN") {
		var probableNewType string
		if len(lx) > 0 {
			parts := strings.Split(lx[0], ": ")
			if len(parts) > 1 {
				probableNewType = parts[1]
			} else {
				probableNewType = lx[0]
			}
		}
		return nil, common.NewNewTypeError(probableNewType)
	}

	// Get year and timezone from email date header
	year := 0
	tz := ""
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateHeader := dateHeaders[0]
		parsedDate := email.ParseDate(dateHeader)
		if parsedDate != nil {
			year = parsedDate.Year()
		}
		// Extract timezone from date header (last element)
		parts := strings.Fields(dateHeader)
		if len(parts) > 0 {
			tz = parts[len(parts)-1]
		}
	}

	// Parse the first log line to extract month, day, time
	if len(lx) == 0 {
		return nil, fmt.Errorf("empty log extract")
	}

	logParts := strings.Fields(lx[0])
	if len(logParts) < 3 {
		return nil, fmt.Errorf("invalid log format")
	}

	month := logParts[0]
	day := logParts[1]
	timeStr := logParts[2]

	// Create event
	event := events.NewEvent("reggerspaul")
	event.EventTypes = []events.EventType{events.NewPortScan()}

	// Set event date
	eventDateStr := fmt.Sprintf("%s %s %d %s %s", day, month, year, timeStr, tz)
	event.EventDate = email.ParseDate(eventDateStr)

	// Extract IP from body (IP=...)
	logPart := strings.Join(lx, "")
	event.IP = common.FindStringWithoutMarkers(body, "IP=", "")

	// Extract source port (SPT=...)
	portStr := common.FindStringWithoutMarkers(logPart, "SPT=", " ")
	if portStr != "" {
		port, err := common.ParsePort(portStr)
		if err == nil {
			event.Port = port
		}
	}

	// Extract target information
	targetIP := common.FindStringWithoutMarkers(logPart, "DST=", " ")
	targetPort := common.FindStringWithoutMarkers(logPart, "DPT=", " ")

	if targetIP != "" || targetPort != "" {
		target := &events.Target{
			IP:   targetIP,
			Port: targetPort,
		}
		event.AddEventDetail(target)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
