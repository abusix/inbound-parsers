// Package serverplan implements the Serverplan parser for DDoS attack reports
package serverplan

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Serverplan parser
type Parser struct{}

// Parse parses emails from @serverplan addresses
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var eventsList []*events.Event

	// Get the email body
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract IP from subject
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	ip := common.ExtractOneIP(subject)
	if ip == "" {
		return nil, common.NewParserError("could not extract IP from subject")
	}

	// Get year from email date
	var year string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		eventDate := email.ParseDate(dateHeaders[0])
		if eventDate != nil {
			year = fmt.Sprintf("%d", eventDate.Year())
		}
	}
	if year == "" {
		return nil, common.NewParserError("could not parse date from headers")
	}

	// Track unique IP-port combinations to avoid duplicates
	ipPortCombinations := make(map[string]bool)

	// Process each line looking for SRC= entries
	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, "SRC=") {
			continue
		}

		// Extract date/time before SRC
		dateTimePart := common.FindStringWithoutMarkers(line, "", "SRC")
		dateTimePart = strings.TrimSpace(dateTimePart)
		parts := strings.Fields(dateTimePart)
		if len(parts) < 3 {
			continue
		}

		// Parse month, day, time
		month := parts[0]
		day := parts[1]
		time := parts[2]

		// Pad day with zero if needed
		if len(day) == 1 {
			day = "0" + day
		}

		// Construct date string
		date := fmt.Sprintf("%s %s %s %s", year, month, day, time)

		// Extract target IP (DST)
		targetIP := common.FindStringWithoutMarkers(line, "DST=", " ")
		if targetIP == "" {
			continue
		}

		// Extract protocol (PROTO)
		protocol := common.FindStringWithoutMarkers(line, "PROTO=", " ")

		// Extract source port (SPT)
		srcPort := common.FindStringWithoutMarkers(line, "SPT=", " ")

		// Extract destination port (DPT) - it's at the end
		targetPort := ""
		if idx := strings.Index(line, "DPT="); idx != -1 {
			remaining := line[idx+4:]
			targetPort = strings.TrimSpace(strings.Fields(remaining)[0])
		}

		if targetPort == "" {
			continue
		}

		// Check for duplicate combination
		combination := fmt.Sprintf("%s-%s:%s", srcPort, targetIP, targetPort)
		if ipPortCombinations[combination] {
			continue
		}
		ipPortCombinations[combination] = true

		// Create event
		event := events.NewEvent("serverplan")
		event.EventTypes = []events.EventType{events.NewDDoS()}

		// Parse and set event date
		eventDate := email.ParseDate(date)
		event.EventDate = eventDate

		event.IP = ip

		// Parse source port
		if srcPort != "" {
			if port, err := common.ParsePort(srcPort); err == nil {
				event.Port = port
			}
		}

		// Add target details
		event.AddEventDetail(&events.Target{
			IP:   targetIP,
			Port: targetPort,
		})

		// Add protocol
		if protocol != "" {
			event.AddEventDetail(&events.TransportProtocol{
				Protocol: protocol,
			})
		}

		eventsList = append(eventsList, event)
	}

	// Fallback: if no events created from log lines, create one from body
	if len(eventsList) == 0 {
		event := events.NewEvent("serverplan")
		event.EventTypes = []events.EventType{events.NewDDoS()}

		// Use email date
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			eventDate := email.ParseDate(dateHeaders[0])
			event.EventDate = eventDate
		}

		event.IP = ip

		// Try to extract target IP from body (look for "ip:" marker)
		bodyLower := strings.ToLower(body)
		targetIP := common.FindStringWithoutMarkers(bodyLower, "ip:", "")
		targetIP = strings.TrimSpace(targetIP)

		if targetIP != "" {
			event.AddEventDetail(&events.Target{
				IP: targetIP,
			})
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
