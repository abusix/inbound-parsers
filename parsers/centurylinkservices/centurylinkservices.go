package centurylinkservices

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

// extractField extracts a field value from a line using regex
// Looks for pattern: field: 'value', and extracts the value
func extractField(line, field string) string {
	parts := strings.Split(line, field)
	if len(parts) < 2 {
		return ""
	}

	// Split on comma to get first part after field
	commaParts := strings.Split(parts[1], ",")
	if len(commaParts) == 0 {
		return ""
	}

	// Extract value between single quotes
	re := regexp.MustCompile(`'([^']*)'`)
	matches := re.FindStringSubmatch(commaParts[0])
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// unwrapLines merges continuation lines into single lines
// Lines starting with a date pattern start new entries, others are continuations
func unwrapLines(lines []string) []string {
	if len(lines) == 0 {
		return []string{}
	}

	datePattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
	var result []string

	for _, line := range lines {
		if datePattern.MatchString(line) {
			// Start of new entry
			result = append(result, line)
		} else if len(result) > 0 {
			// Continuation of previous entry
			result[len(result)-1] += strings.TrimLeft(line, " \t")
		}
	}

	return result
}

// parseOpenEvent parses an Open vulnerability event
func parseOpenEvent(line string) *events.Event {
	// Parse: date time ip ... fields
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}

	date := fields[0]
	time := fields[1]
	ip := fields[2]

	subtype := extractField(line, "subtype")
	protocol := extractField(line, "protocol")
	asn := extractField(line, "asn")
	port := extractField(line, "port")
	naics := extractField(line, "naics")

	event := events.NewEvent("centurylinkservices")
	event.IP = ip
	event.EventDate = email.ParseDate(fmt.Sprintf("%s %s", date, time))

	if port != "" {
		if portNum, err := common.ParsePort(port); err == nil {
			event.Port = portNum
		}
	}

	if asn != "" {
		event.AddEventDetail(&events.ASN{ASN: asn})
	}
	if protocol != "" {
		event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})
	}
	if naics != "" {
		event.AddEventDetail(&events.NAICS{NAICS: naics})
	}

	event.EventTypes = []events.EventType{events.NewOpen(subtype)}
	return event
}

// parseMalwareEvent parses a Malware/virus event
func parseMalwareEvent(line string) *events.Event {
	// Parse: date time ip ... fields
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}

	date := fields[0]
	time := fields[1]
	ip := fields[2]

	mwtype := extractField(line, "mwtype")
	protocol := extractField(line, "protocol")
	asn := extractField(line, "asn")
	srcport := extractField(line, "srcport")
	naics := extractField(line, "naics")
	url := extractField(line, "C&C")
	dstip := extractField(line, "dstip")
	dstport := extractField(line, "dstport")

	event := events.NewEvent("centurylinkservices")
	event.IP = ip
	event.EventDate = email.ParseDate(fmt.Sprintf("%s %s", date, time))

	if srcport != "" {
		if portNum, err := common.ParsePort(srcport); err == nil {
			event.Port = portNum
		}
	}

	if url != "" || dstip != "" || dstport != "" {
		event.AddEventDetail(&events.CommandAndControl{
			URL:  url,
			IP:   dstip,
			Port: dstport,
		})
	}

	if asn != "" {
		event.AddEventDetail(&events.ASN{ASN: asn})
	}
	if protocol != "" {
		event.AddEventDetail(&events.TransportProtocol{Protocol: protocol})
	}
	if naics != "" {
		event.AddEventDetail(&events.NAICS{NAICS: naics})
	}

	event.EventTypes = []events.EventType{events.NewMalware(mwtype)}
	return event
}

// parseSpam parses spam reports
func parseSpam(body, subjectLower string) ([]*events.Event, error) {
	// Extract IP from Received header: Received:.*(\[.*\])
	ipPattern := regexp.MustCompile(`Received:.*\[([^\]]+)\]`)
	ipMatches := ipPattern.FindAllStringSubmatch(body, -1)
	if len(ipMatches) == 0 {
		return nil, common.NewParserError("no IP found in Received headers")
	}
	ip := ipMatches[len(ipMatches)-1][1] // Last match

	// Extract date from Date header
	datePattern := regexp.MustCompile(`Date:(.*)`)
	dateMatches := datePattern.FindAllStringSubmatch(body, -1)
	var dateStr string
	if len(dateMatches) > 0 {
		dateStr = strings.TrimSpace(dateMatches[len(dateMatches)-1][1])
	}

	event := events.NewEvent("centurylinkservices")
	event.IP = ip
	if dateStr != "" {
		event.EventDate = email.ParseDate(dateStr)
	}
	event.EventTypes = []events.EventType{events.NewSpam()}

	return []*events.Event{event}, nil
}

// parseBody parses the email body based on subject type
func parseBody(body, subjectLower string) ([]*events.Event, error) {
	var parseEvent func(string) *events.Event

	// Determine event type from subject
	if strings.Contains(subjectLower, "vulnerabilities") {
		parseEvent = parseOpenEvent
	} else if strings.Contains(subjectLower, "virus infected") {
		parseEvent = parseMalwareEvent
	} else if strings.Contains(subjectLower, "bulk") || strings.Contains(subjectLower, "spam") {
		return parseSpam(body, subjectLower)
	} else {
		return nil, common.NewParserError(fmt.Sprintf("unknown email type: %s", subjectLower))
	}

	// Get lines around the === separator
	lines := common.GetBlockAround(body, "===")
	if len(lines) < 3 {
		return nil, common.NewParserError("no data block found")
	}

	// Skip first 2 lines (header info)
	lines = lines[2:]

	// Unwrap continuation lines
	lines = unwrapLines(lines)

	// Reverse lines - most recent date is at the bottom
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}

	// Parse events and deduplicate by IP-subtype combination
	events := []*events.Event{}
	seen := make(map[string]bool)

	for _, line := range lines {
		event := parseEvent(line)
		if event == nil {
			continue
		}

		// Get subtype for deduplication
		subtype := extractField(line, "subtype")
		if subtype == "" {
			subtype = extractField(line, "mwtype")
		}

		// Deduplicate by IP-subtype combination
		key := fmt.Sprintf("%s-%s", event.IP, subtype)
		if !seen[key] {
			seen[key] = true
			events = append(events, event)
		}
	}

	return events, nil
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

	parsedEvents, err := parseBody(body, strings.ToLower(subject))
	if err != nil {
		return nil, err
	}

	if len(parsedEvents) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return parsedEvents, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
