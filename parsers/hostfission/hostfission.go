package hostfission

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

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Convert body to lowercase for comparison
	bodyLower := strings.ToLower(body)

	// Check if this is a brute force report
	if !strings.Contains(bodyLower, "brute force") {
		return nil, common.NewNewTypeError(subject)
	}

	// Parse entries from the body
	// Pattern: (IP),(IP),(protocol),(type),count,(date)
	// Example: 192.168.1.1,192.168.1.2,tcp,ssh,5,2024-01-15 10:30:00
	pattern := regexp.MustCompile(`([\d|\.]+),([\d|\.]+),([a-z]+),[a-z]+,\d*,([^\n]+)`)
	matches := pattern.FindAllStringSubmatch(bodyLower, -1)

	if len(matches) == 0 {
		return nil, common.NewParserError("no event created")
	}

	var result []*events.Event

	for _, match := range matches {
		if len(match) < 5 {
			continue
		}

		event := events.NewEvent("hostfission")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		// Source IP (first IP in the pattern)
		event.IP = match[1]

		// Target IP (second IP in the pattern)
		target := &events.Target{
			IP: match[2],
		}
		event.AddEventDetail(target)

		// Transport protocol (third field)
		protocol := &events.TransportProtocol{
			Protocol: match[3],
		}
		event.AddEventDetail(protocol)

		// Event date (fourth field)
		eventDateStr := strings.TrimSpace(match[4])
		event.EventDate = email.ParseDate(eventDateStr)

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, common.NewParserError("no event created")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
