package watchdog

import (
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

// parseTable parses the table format in Watchdog emails
func parseTable(body, subject string, dateStr string) []*events.Event {
	bodyLower := strings.ToLower(body)
	var timezone string

	// Extract timezone
	if strings.Contains(bodyLower, "our timezone is") {
		timezone = common.FindStringWithoutMarkers(bodyLower, "our timezone is", ".")
	} else if strings.Contains(bodyLower, "adjusted to our") {
		timezone = common.FindStringWithoutMarkers(bodyLower, "adjusted to our", "timezone")
	}
	timezone = strings.ToUpper(strings.TrimSpace(timezone))

	// Create event list
	var result []*events.Event

	// Get log block starting from "DateTime" header
	lines := getBlockAroundContinueUntilEnd(body, "DateTime")
	if len(lines) == 0 {
		return result
	}

	// Check if this is a special case with "Dest Port" in body
	if strings.Contains(body, "Dest Port") {
		// WHY, everywhere there are at least two spaces in between columns, BUT NOT HERE
		// return a very simple event
		event := events.NewEvent("watchdog")
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
		event.IP = subject
		if dateStr != "" {
			event.EventDate = email.ParseDate(dateStr)
		}
		return []*events.Event{event}
	}

	// Parse headers from first line
	if len(lines) == 0 {
		return result
	}

	headers := strings.Fields(lines[0])
	// Remove "AttackClass" if present
	var filteredHeaders []string
	for _, h := range headers {
		if h != "AttackClass" {
			filteredHeaders = append(filteredHeaders, h)
		}
	}
	headers = filteredHeaders

	// Parse data lines
	lineNumberPattern := regexp.MustCompile(`^\s*\d+`)
	for i := 1; i < len(lines); i++ {
		line := lines[i]

		if strings.TrimSpace(line) == "" {
			// skip empty lines
			continue
		}

		if !lineNumberPattern.MatchString(line) {
			// all log lines start with a number, after that we are done
			break
		}

		// Split by two or more spaces (this is how columns are separated)
		fields := splitByDoubleSpace(line)
		if len(fields) != len(headers)+1 {
			// ignore lines where fields don't match up with headers
			continue
		}

		// Create a map from headers to field values (skip first field which is line number)
		log := make(map[string]string)
		for j, header := range headers {
			if j+1 < len(fields) {
				log[header] = fields[j+1]
			}
		}

		// Create event
		event := events.NewEvent("watchdog")
		event.EventTypes = []events.EventType{events.NewMaliciousActivity()}

		// Set event date
		if dateTime, ok := log["DateTime"]; ok {
			dateStr := strings.TrimSpace(dateTime) + " " + timezone
			event.EventDate = email.ParseDate(dateStr)
		}

		// Set source IP
		if sourceIP, ok := log["SourceIP"]; ok {
			event.IP = sourceIP
		}

		// Set source port
		if srcPort, ok := log["Srcport"]; ok {
			if port, err := common.ParsePort(srcPort); err == nil {
				event.Port = port
			}
		}

		// Set protocol
		if protocol, ok := log["Protocol"]; ok {
			event.AddEventDetail(&events.TransportProtocol{
				Protocol: protocol,
			})
		}

		// Set destination/target
		if destIP, ok := log["DestinationIP"]; ok {
			target := &events.Target{
				IP: strings.TrimSpace(destIP),
			}
			if destPort, ok := log["DestPort"]; ok {
				target.Port = strings.TrimSpace(destPort)
			}
			event.AddEventDetail(target)
		} else if dest, ok := log["Destination"]; ok {
			// this might sometimes be a string and not an IP
			// we'll try to add it anyway, validation happens elsewhere
			target := &events.Target{
				IP: strings.TrimSpace(dest),
			}
			event.AddEventDetail(target)
		}

		result = append(result, event)
	}

	return result
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Get date header
	var dateStr string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		dateStr = dateHeaders[0]
	}

	parsedEvents := parseTable(body, subject, dateStr)
	return parsedEvents, nil
}

// getBlockAroundContinueUntilEnd is a specialized version of GetBlockAround that continues until end
// This matches the Python get_block_around with continue_until_end=True
func getBlockAroundContinueUntilEnd(text, marker string) []string {
	lines := strings.Split(text, "\n")
	var block []string
	var result []string
	foundStart := false

	for _, line := range lines {
		if strings.Contains(line, marker) {
			foundStart = true
			// Yield the accumulated block first
			for _, b := range block {
				result = append(result, b)
			}
		}
		if foundStart {
			// Continue until end - don't stop at empty lines
			result = append(result, line)
		} else if strings.TrimSpace(line) == "" {
			// Reset block on empty line
			block = nil
		} else {
			// Accumulate non-empty lines before marker
			block = append(block, line)
		}
	}

	return result
}

// splitByDoubleSpace splits a string by two or more consecutive spaces, filtering out empty results
func splitByDoubleSpace(s string) []string {
	// Split by two or more spaces
	parts := regexp.MustCompile(`  +`).Split(s, -1)

	// Filter out empty strings
	var result []string
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
