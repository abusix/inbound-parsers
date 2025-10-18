package internet2

import (
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Check for "TCP connection attempt" in body
	if !strings.Contains(body, "TCP connection attempt") {
		return nil, common.NewNewTypeError(subject)
	}

	// Get continuous lines starting from the CSV header
	eventBlock := common.GetContinuousLinesUntilEmptyLine(
		body,
		"deviceReceptionTime_UTC,sourceAddress,sourcePort,destinationAddress,destinationPort",
	)

	if len(eventBlock) == 0 {
		return nil, common.NewParserError("no event data found in body")
	}

	var result []*events.Event
	seenIPs := make(map[string]bool)

	// Parse each line of the event block (skip header if present)
	for _, eventLine := range eventBlock {
		// Skip header line
		if strings.Contains(eventLine, "deviceReceptionTime_UTC") {
			continue
		}

		eventLine = strings.TrimSpace(eventLine)
		if eventLine == "" {
			continue
		}

		// Split CSV line: date, ip, port, destination_ip, destination_port
		parts := strings.Split(eventLine, ",")
		if len(parts) < 5 {
			continue
		}

		date := strings.TrimSpace(parts[0])
		ip := strings.TrimSpace(parts[1])
		port := strings.TrimSpace(parts[2])
		destinationIP := strings.TrimSpace(parts[3])
		destinationPort := strings.TrimSpace(parts[4])

		// Skip duplicate IPs (Python logic: if ip not in ips)
		if seenIPs[ip] {
			continue
		}
		seenIPs[ip] = true

		// Create event with PortScan event type
		event := events.NewEvent("internet2")
		event.EventTypes = []events.EventType{events.NewPortScan()}

		// Set event date from the CSV data
		event.EventDate = email.ParseDate(date)

		// Set IP
		event.IP = ip

		// Try to set port (Python has try/except ValueError)
		if portInt, err := common.ParsePort(port); err == nil {
			event.Port = portInt
		}

		// Add target details (Python: event.add_event_detail(Target(...)))
		// Python has try/except ValueError for this too
		target := &events.Target{
			IP:   destinationIP,
			Port: destinationPort,
		}
		event.AddEventDetail(target)

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no events parsed from email body")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
