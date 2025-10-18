// Package netum implements the Netum parser for login attack reports
package netum

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the Netum parser
type Parser struct{}

// Parse parses emails from abuse@netum.com.br
// The emails contain exim_reject logs with login attack information
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract IP from subject line (format: "IP: xxx.xxx.xxx.xxx")
	ip := common.FindStringWithoutMarkers(subject+"\n", "IP: ", "\n")
	if ip == "" {
		return nil, common.NewParserError("IP not found in subject")
	}

	// Clean IP
	ip = common.IsIP(ip)
	if ip == "" {
		return nil, common.NewParserError("invalid IP in subject")
	}

	// Extract target IP from body (format: "victim) IP is: xxx.xxx.xxx.xxx")
	target := common.FindStringWithoutMarkers(body, "victim) IP is:", "\n")
	target = strings.TrimSpace(target)
	target = common.IsIP(target)

	// Get continuous lines starting from "exim_reject:" marker until empty line
	lines := common.GetContinuousLinesUntilEmptyLine(body, "exim_reject:")
	if len(lines) == 0 {
		return nil, common.NewParserError("no exim_reject lines found")
	}

	var eventsList []*events.Event

	for _, line := range lines {
		event := events.NewEvent("netum")

		// Set source IP
		event.IP = ip

		// Parse date from line (first two words) and add timezone
		// Format: "YYYY-MM-DD HH:MM:SS"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			dateStr := parts[0] + " " + parts[1] + " -03:00"
			eventDate := email.ParseDate(dateStr)
			event.EventDate = eventDate
		}

		// Extract port from line
		// Format: "... [ip]:port ..."
		// Looking for text after "[ip]:" and before next space
		portStr := common.FindStringWithoutMarkers(line, ip+"]:", ":")
		portStr = strings.Fields(portStr)[0]
		if portStr != "" {
			port, err := common.ParsePort(portStr)
			if err == nil {
				event.Port = port
			}
		}

		// Set event type
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		// Add target IP if found
		if target != "" {
			event.AddEventDetail(&events.Target{IP: target})
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
