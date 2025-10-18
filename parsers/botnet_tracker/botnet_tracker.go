package botnet_tracker

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

var (
	// Regex patterns from Python
	scanLogPattern = regexp.MustCompile(
		`\(time.*=(?P<date>.*?)\s\(attacker's IP\)=(?P<ip>.*?)\s\(IP being \w+\)=` +
		`(?P<scan>.*?)\s(\(TCP.*=(?P<port>.*))?.*`,
	)
	passwordLogPattern = regexp.MustCompile(
		`(?P<datetime>.*? .*?)\s.+:.+user (?P<user>\S+)?\s?from (?P<ip>\S+) port (?P<port>\d+).*`,
	)
)

type Parser struct {
	base.BaseParser
}

// New creates a new botnet_tracker parser instance
// Accepts parameters for compatibility with the registry but doesn't use them
func New(serializedEmail email.SerializedEmail, fromAddr, fromName, contentType string) *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("botnet_tracker"),
	}
}

func NewParser() *Parser {
	return &Parser{
		BaseParser: base.NewBaseParser("botnet_tracker"),
	}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil || body == "" {
		return nil, common.NewParserError("email body is empty")
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil || subject == "" {
		return nil, common.NewParserError("subject is empty")
	}

	// Normalize line endings
	body = strings.ReplaceAll(body, "\r\n", "\n")
	subject = strings.ReplaceAll(subject, "\r\n", "")
	subject = strings.ReplaceAll(subject, "\n", "")

	var eventsList []*events.Event

	if strings.Contains(subject, "botnet computers attached") {
		eventsList = p.parseBotnetAttached(body, serializedEmail)
	} else if strings.Contains(subject, "botnet computers listed") {
		eventsList = p.parseBotnetListed(body, serializedEmail)
	} else {
		return nil, common.NewParserError("unknown subject format")
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// parseBotnetAttached handles "botnet computers attached" subject format
func (p *Parser) parseBotnetAttached(body string, serializedEmail *email.SerializedEmail) []*events.Event {
	var eventsList []*events.Event

	marker := "\n---- connection log"
	startIdx := strings.Index(body, marker)
	if startIdx == -1 {
		return eventsList
	}
	startIdx += len(marker)

	// Find the header line
	startIdx = strings.Index(body[startIdx:], "\n")
	if startIdx == -1 {
		return eventsList
	}
	startIdx = strings.Index(body, marker) + len(marker) + startIdx + 1

	endIdx := strings.Index(body[startIdx:], "\n")
	if endIdx == -1 {
		return eventsList
	}
	endIdx += startIdx

	// Parse headers
	headerLine := body[startIdx:endIdx]
	tmp := strings.Split(headerLine, "=>")
	var headers []string
	for _, part := range tmp {
		header := strings.TrimSpace(part)
		header = strings.ToLower(header)
		header = strings.ReplaceAll(header, " ", "_")
		header = strings.ReplaceAll(header, "#", "")
		headers = append(headers, header)
	}

	// Find data section
	dataMarker := "----\n"
	dataStartIdx := strings.Index(body[endIdx:], dataMarker)
	if dataStartIdx == -1 {
		return eventsList
	}
	dataStartIdx = endIdx + dataStartIdx + len(dataMarker)

	dataEndIdx := strings.Index(body[dataStartIdx:], "\n---- ")
	if dataEndIdx == -1 {
		dataEndIdx = len(body)
	} else {
		dataEndIdx += dataStartIdx
	}

	dataBody := strings.TrimSpace(body[dataStartIdx:dataEndIdx])
	lines := strings.Split(dataBody, "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		event := p.appendEvent(headers, line)
		if event != nil {
			eventsList = append(eventsList, event)
		}
	}

	return eventsList
}

// appendEvent creates an event from a line in "botnet computers attached" format
func (p *Parser) appendEvent(headers []string, line string) *events.Event {
	event := events.NewEvent("botnet_tracker")
	fields := strings.Fields(line)

	if len(fields) < 4 {
		return nil
	}

	// Extract IP (field 3, 0-indexed)
	if len(fields) > 3 {
		event.IP = fields[3]
	} else {
		return nil
	}

	// Extract date (fields 0, 1, 2)
	if len(fields) >= 3 {
		dateStr := fmt.Sprintf("%s %s %s", fields[0], fields[1], fields[2])
		parsedDate := email.ParseDate(dateStr)
		event.EventDate = parsedDate
	}

	event.EventTypes = []events.EventType{events.NewSpam()}

	// Add headers
	if event.Headers == nil {
		event.Headers = make(map[string]interface{})
	}
	for idx, headerValue := range headers {
		if idx < len(fields) {
			event.Headers[headerValue] = strings.ToLower(fields[idx])
		}
	}

	return event
}

// parseBotnetListed handles "botnet computers listed" subject format
func (p *Parser) parseBotnetListed(body string, serializedEmail *email.SerializedEmail) []*events.Event {
	var eventsList []*events.Event

	marker := "-------------------------------------------------------------------------------"

	// If marker not found in main body, try first part
	if !strings.Contains(body, marker) {
		if len(serializedEmail.Parts) > 1 {
			if partBody, ok := serializedEmail.Parts[1].Body.(string); ok {
				body = partBody
			} else if partBytes, ok := serializedEmail.Parts[1].Body.([]byte); ok {
				body = string(partBytes)
			}
		}

		if !strings.Contains(body, marker) {
			return eventsList
		}
	}

	lines := common.GetContinuousLinesUntilEmptyLine(body, marker)

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Try password log pattern first
		if matches := passwordLogPattern.FindStringSubmatch(line); matches != nil {
			event := p.parseLoginAttack(matches)
			if event != nil {
				eventsList = append(eventsList, event)
			}
			continue
		}

		// Try scan log pattern
		if matches := scanLogPattern.FindStringSubmatch(line); matches != nil {
			event := p.parseIPScan(matches)
			if event != nil {
				eventsList = append(eventsList, event)
			}
			continue
		}
	}

	return eventsList
}

// parseLoginAttack creates a LoginAttack event from regex matches
func (p *Parser) parseLoginAttack(matches []string) *events.Event {
	event := events.NewEvent("botnet_tracker")

	// Extract named groups manually since Go doesn't provide named group maps directly
	// Pattern: (?P<datetime>.*? .*?)\s.+:.+user (?P<user>\S+)?\s?from (?P<ip>\S+) port (?P<port>\d+).*
	// Groups: 0=full, 1=datetime, 2=user, 3=ip, 4=port

	if len(matches) < 4 {
		return nil
	}

	// datetime (group 1)
	if len(matches) > 1 && matches[1] != "" {
		parsedDate := email.ParseDate(matches[1])
		event.EventDate = parsedDate
	}

	// ip (group 3)
	if len(matches) > 3 && matches[3] != "" {
		event.IP = matches[3]
	} else {
		return nil
	}

	// port (group 4)
	if len(matches) > 4 && matches[4] != "" {
		if port, err := strconv.Atoi(matches[4]); err == nil {
			event.Port = port
		}
	}

	// user (group 2) - used in LoginAttack event type
	username := ""
	if len(matches) > 2 && matches[2] != "" {
		username = matches[2]
	}

	event.EventTypes = []events.EventType{events.NewLoginAttack(username, "")}

	return event
}

// parseIPScan creates a PortScan event from regex matches
func (p *Parser) parseIPScan(matches []string) *events.Event {
	event := events.NewEvent("botnet_tracker")

	// Pattern groups: 0=full, 1=date, 2=ip, 3=scan, 4=port_group, 5=port
	// Named groups: date, ip, scan, port

	if len(matches) < 4 {
		return nil
	}

	// date (group 1)
	if len(matches) > 1 && matches[1] != "" {
		dateStr := matches[1]
		// Try to parse with standard formats first
		parsedDate := email.ParseDate(dateStr)

		// If standard parsing fails, try the Python fallback format
		if parsedDate == nil {
			// Python: date.replace('/', '\r').split('.')[0].replace(':', '\r', 1)
			// This is a complex transformation - let's try common formats
			formats := []string{
				"2006/01/02 15:04:05",
				"2006-01-02 15:04:05",
				"01/02/2006 15:04:05",
				"02/01/2006 15:04:05",
			}
			for _, format := range formats {
				if t, err := time.Parse(format, dateStr); err == nil {
					parsedDate = &t
					break
				}
			}
		}

		event.EventDate = parsedDate
	}

	// ip (group 2)
	if len(matches) > 2 && matches[2] != "" {
		event.IP = matches[2]
	} else {
		return nil
	}

	// scan (target IP, group 3)
	var target *events.Target
	if len(matches) > 3 && matches[3] != "" {
		targetIP := strings.ReplaceAll(matches[3], "^", ".")
		target = &events.Target{
			IP: targetIP,
		}
	} else {
		return nil
	}

	// port (group 5 or last match)
	if len(matches) > 5 && matches[5] != "" {
		target.Port = matches[5]
	}

	event.EventTypes = []events.EventType{events.NewPortScan()}
	event.AddEventDetail(target)

	return event
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
